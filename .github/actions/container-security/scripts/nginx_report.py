from collections import Counter
from html import escape
from pathlib import Path
import json
import os

import yaml


RESULTS_DIR = Path("results")

POLICY_FILE = Path(
    os.environ.get(
        "CONTAINER_SECURITY_POLICY",
        "container-security-policy.yml",
    )
)


def read_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def read_text(path):
    return path.read_text(
        encoding="utf-8"
    ).strip()


def html(value):
    return escape(
        str(value),
        quote=False,
    )


def analyse_nginx(variant):
    directory = (
        RESULTS_DIR
        / variant
    )

    image = read_text(
        directory
        / "nginx-image.txt"
    )

    sbom = read_json(
        directory
        / "nginx-sbom.spdx.json"
    )

    trivy = read_json(
        directory
        / "nginx-trivy-image.json"
    )

    total = Counter()
    fixable = Counter()

    findings = []

    for result in trivy.get(
        "Results",
        [],
    ):
        for finding in (
            result.get(
                "Vulnerabilities"
            )
            or []
        ):
            severity = finding.get(
                "Severity",
                "UNKNOWN",
            ).upper()

            fixed_version = (
                finding.get(
                    "FixedVersion"
                )
                or ""
            ).strip()

            total[
                severity
            ] += 1

            if fixed_version:
                fixable[
                    severity
                ] += 1

            findings.append({
                "id": (
                    finding.get(
                        "VulnerabilityID"
                    )
                    or "UNKNOWN"
                ),
                "package": (
                    finding.get(
                        "PkgName"
                    )
                    or "unknown"
                ),
                "severity": severity,
                "installed_version": (
                    finding.get(
                        "InstalledVersion"
                    )
                    or ""
                ),
                "fixed_version": (
                    fixed_version
                ),
            })

    return {
        "image": image,
        "sbom_packages": len(
            sbom.get(
                "packages",
                [],
            )
        ),
        "total": dict(
            total
        ),
        "fixable": dict(
            fixable
        ),
        "findings": findings,
    }


def counter_value(
    counter,
    severity,
):
    return counter.get(
        severity,
        0,
    )


def main():
    policy = yaml.safe_load(
        POLICY_FILE.read_text(
            encoding="utf-8"
        )
    )

    baseline = analyse_nginx(
        "baseline"
    )

    hardened = analyse_nginx(
        "hardened"
    )

    approved_image = (
        policy
        .get(
            "images",
            {},
        )
        .get(
            "nginx"
        )
    )

    image_ok = (
        approved_image is not None
        and hardened[
            "image"
        ] == approved_image
    )

    os_policy = (
        policy[
            "gate"
        ][
            "os_vulnerabilities"
        ]
    )

    if os_policy.get(
        "require_fix_available",
        False,
    ):
        vulnerability_source = (
            hardened[
                "fixable"
            ]
        )

        qualifier = (
            "fixable"
        )
    else:
        vulnerability_source = (
            hardened[
                "total"
            ]
        )

        qualifier = (
            "detected"
        )

    blocking_findings = sum(
        counter_value(
            vulnerability_source,
            severity,
        )
        for severity
        in os_policy[
            "severities"
        ]
    )

    vulnerabilities_ok = (
        blocking_findings == 0
    )

    nginx_passed = (
        image_ok
        and vulnerabilities_ok
    )

    checks = [
        {
            "name": (
                "Nginx — approved image"
            ),
            "passed": image_ok,
            "detail": (
                hardened[
                    "image"
                ]
                if image_ok
                else (
                    "expected "
                    f"{approved_image}, "
                    "received "
                    f"{hardened['image']}"
                )
            ),
        },
        {
            "name": (
                "Nginx CVEs — Trivy Image"
            ),
            "passed": (
                vulnerabilities_ok
            ),
            "detail": (
                f"{blocking_findings} "
                f"{qualifier} "
                "blocking findings"
            ),
        },
    ]

    comparison_path = (
        RESULTS_DIR
        / "comparison.json"
    )

    comparison = read_json(
        comparison_path
    )

    comparison[
        "nginx"
    ] = {
        "baseline": baseline,
        "hardened": hardened,
        "approved_image": (
            approved_image
        ),
        "gate": {
            "passed": (
                nginx_passed
            ),
            "checks": checks,
        },
    }

    comparison[
        "pipeline_gate"
    ][
        "checks"
    ].extend(
        checks
    )

    nginx_failures = [
        check
        for check
        in checks
        if not check[
            "passed"
        ]
    ]

    comparison[
        "pipeline_gate"
    ][
        "failures"
    ].extend(
        nginx_failures
    )

    comparison[
        "pipeline_gate"
    ][
        "passed"
    ] = (
        comparison[
            "pipeline_gate"
        ][
            "passed"
        ]
        and nginx_passed
    )

    comparison_path.write_text(
        json.dumps(
            comparison,
            indent=2,
        ),
        encoding="utf-8",
    )

    image_changed = (
        baseline[
            "image"
        ]
        != hardened[
            "image"
        ]
    )

    status_icon = (
        "✅"
        if nginx_passed
        else "❌"
    )

    status_text = (
        "PASS"
        if nginx_passed
        else "FAIL"
    )

    section = [
        "## Nginx image — Syft + Trivy",
        "",
        "<table>",
        "<thead>",
        "<tr>",
        "<th>Control</th>",
        "<th>Baseline</th>",
        "<th>Final</th>",
        "</tr>",
        "</thead>",
        "<tbody>",

        "<tr>",
        "<td>Container image</td>",
        (
            f"<td><code>"
            f"{html(baseline['image'])}"
            f"</code></td>"
        ),
        (
            f"<td><code>"
            f"{html(hardened['image'])}"
            f"</code></td>"
        ),
        "</tr>",

        "<tr>",
        "<td>Syft SBOM packages</td>",
        (
            f"<td>"
            f"{baseline['sbom_packages']}"
            f"</td>"
        ),
        (
            f"<td>"
            f"{hardened['sbom_packages']}"
            f"</td>"
        ),
        "</tr>",

        "<tr>",
        "<td>HIGH CVEs</td>",
        (
            f"<td>"
            f"{counter_value(baseline['total'], 'HIGH')}"
            f"</td>"
        ),
        (
            f"<td>"
            f"{counter_value(hardened['total'], 'HIGH')}"
            f"</td>"
        ),
        "</tr>",

        "<tr>",
        "<td>CRITICAL CVEs</td>",
        (
            f"<td>"
            f"{counter_value(baseline['total'], 'CRITICAL')}"
            f"</td>"
        ),
        (
            f"<td>"
            f"{counter_value(hardened['total'], 'CRITICAL')}"
            f"</td>"
        ),
        "</tr>",

        "<tr>",
        "<td>Fixable blocking CVEs</td>",
        "<td>—</td>",
        (
            f"<td>"
            f"{blocking_findings}"
            f"</td>"
        ),
        "</tr>",

        "</tbody>",
        "</table>",
        "",
    ]

    if image_changed:
        section.extend([
            (
                f"**Image policy remediation:** "
                f"`{baseline['image']}` → "
                f"`{hardened['image']}`"
            ),
            "",
        ])

    section.extend([
        (
            f"**Nginx gate:** "
            f"{status_icon} {status_text}"
        ),
        "",
        (
            f"- Approved image: "
            f"`{approved_image}`"
        ),
        (
            f"- {blocking_findings} "
            f"{qualifier} blocking "
            "HIGH/CRITICAL finding(s)."
        ),
    ])

    markdown_path = (
        RESULTS_DIR
        / "comparison.md"
    )

    markdown = (
        markdown_path.read_text(
            encoding="utf-8"
        )
    )

    nginx_markdown = (
        "\n".join(
            section
        )
    )

    marker = (
        "## Pipeline gate"
    )

    if marker in markdown:
        markdown = (
            markdown.replace(
                marker,
                nginx_markdown
                + "\n\n"
                + marker,
                1,
            )
        )
    else:
        markdown += (
            "\n\n"
            + nginx_markdown
            + "\n"
        )

    if image_changed:
        markdown = (
            markdown.replace(
                "## Security assessment",
                "## Remediation summary",
                1,
            )
        )

    if not nginx_passed:
        markdown = (
            markdown.replace(
                "## ✅ Pipeline result: PASS",
                "## ❌ Pipeline result: FAIL",
                1,
            )
        )

    markdown_path.write_text(
        markdown,
        encoding="utf-8",
    )

    print()
    print(
        "NGINX SECURITY ASSESSMENT"
    )
    print(
        "========================="
    )
    print()

    print(
        f"Baseline image .... "
        f"{baseline['image']}"
    )

    print(
        f"Final image ....... "
        f"{hardened['image']}"
    )

    print(
        f"SBOM packages ..... "
        f"{baseline['sbom_packages']}"
        " -> "
        f"{hardened['sbom_packages']}"
    )

    print(
        f"HIGH CVEs ......... "
        f"{counter_value(baseline['total'], 'HIGH')}"
        " -> "
        f"{counter_value(hardened['total'], 'HIGH')}"
    )

    print(
        f"CRITICAL CVEs ..... "
        f"{counter_value(baseline['total'], 'CRITICAL')}"
        " -> "
        f"{counter_value(hardened['total'], 'CRITICAL')}"
    )

    print(
        f"Blocking findings . "
        f"{blocking_findings}"
    )

    print(
        f"NGINX RESULT ...... "
        f"{status_text}"
    )

    print()

    if not nginx_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
