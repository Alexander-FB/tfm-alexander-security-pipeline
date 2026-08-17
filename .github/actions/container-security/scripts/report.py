from collections import Counter
from pathlib import Path
import json
import os
import re

import yaml


RESULTS_DIR = Path("results")

POLICY_FILE = Path(
    os.environ.get(
        "CONTAINER_SECURITY_POLICY",
        "container-security-policy.yml",
    )
)

BASELINE = "baseline"
HARDENED = "hardened"

BLOCKING_SEVERITIES = (
    "HIGH",
    "CRITICAL",
)


# ---------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------

def read_json(path):
    with path.open() as file:
        return json.load(file)


def counter_value(counter, severity):
    return counter.get(severity, 0)


def high_critical(counter):
    return sum(
        counter_value(counter, severity)
        for severity in BLOCKING_SEVERITIES
    )


def yes_no(value):
    if value is True:
        return "Yes"

    if value is False:
        return "No"

    return "Unknown"


def pass_fail(value):
    return "PASS" if value else "FAIL"


def delta(before, after):
    value = after - before

    if value > 0:
        return f"+{value}"

    return str(value)


# ---------------------------------------------------------------------
# SBOM — Syft
# ---------------------------------------------------------------------

def parse_sbom(variant):
    data = read_json(
        RESULTS_DIR
        / variant
        / "sbom.spdx.json"
    )

    return {
        "package_entries": len(
            data.get("packages", [])
        )
    }


# ---------------------------------------------------------------------
# Vulnerabilities — Trivy Image
# ---------------------------------------------------------------------

def parse_vulnerabilities(variant):
    data = read_json(
        RESULTS_DIR
        / variant
        / "trivy-image.json"
    )

    result = {
        "os": {
            "total": Counter(),
            "fixable": Counter(),
            "no_fix_reported": Counter(),
            "findings": [],
        },
        "application": {
            "total": Counter(),
            "fixable": Counter(),
            "no_fix_reported": Counter(),
            "findings": [],
        },
    }

    os_types = {
        "debian",
        "ubuntu",
        "alpine",
        "redhat",
        "rocky",
        "amazon",
        "oracle",
        "suse",
    }

    for scan_result in data.get("Results", []):
        scan_class = scan_result.get(
            "Class",
            ""
        )

        scan_type = scan_result.get(
            "Type",
            ""
        )

        if (
            scan_class == "os-pkgs"
            or scan_type in os_types
        ):
            category = "os"

        elif scan_class == "lang-pkgs":
            category = "application"

        else:
            category = "application"

        findings = (
            scan_result.get(
                "Vulnerabilities"
            )
            or []
        )

        for finding in findings:
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

            installed_version = (
                finding.get(
                    "InstalledVersion"
                )
                or ""
            ).strip()

            vulnerability_id = (
                finding.get(
                    "VulnerabilityID"
                )
                or "UNKNOWN"
            )

            package = (
                finding.get(
                    "PkgName"
                )
                or "unknown"
            )

            status = (
                finding.get(
                    "Status"
                )
                or "unknown"
            )

            title = (
                finding.get(
                    "Title"
                )
                or ""
            )

            result[
                category
            ]["total"][severity] += 1

            if fixed_version:
                result[
                    category
                ]["fixable"][severity] += 1
            else:
                result[
                    category
                ]["no_fix_reported"][severity] += 1

            result[
                category
            ]["findings"].append({
                "id": vulnerability_id,
                "package": package,
                "severity": severity,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "status": status,
                "title": title,
            })

    return result


def representative_os_findings(
    vulnerability_data,
    limit=4,
):
    findings = vulnerability_data[
        "os"
    ]["findings"]

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNKNOWN": 4,
    }

    relevant = [
        finding
        for finding in findings
        if finding["severity"]
        in BLOCKING_SEVERITIES
    ]

    relevant.sort(
        key=lambda finding: (
            0 if not finding["fixed_version"] else 1,
            severity_order.get(
                finding["severity"],
                99,
            ),
            finding["id"],
            finding["package"],
        )
    )

    # One representative package per CVE.
    unique = []
    seen_ids = set()

    for finding in relevant:
        if finding["id"] in seen_ids:
            continue

        seen_ids.add(
            finding["id"]
        )

        unique.append(
            finding
        )

        if len(unique) >= limit:
            break

    return unique


# ---------------------------------------------------------------------
# Misconfigurations — Trivy Config
# ---------------------------------------------------------------------

def parse_misconfigurations(variant):
    data = read_json(
        RESULTS_DIR
        / variant
        / "trivy-config.json"
    )

    counts = Counter()

    for scan_result in data.get("Results", []):
        findings = (
            scan_result.get(
                "Misconfigurations"
            )
            or []
        )

        for finding in findings:
            severity = finding.get(
                "Severity",
                "UNKNOWN",
            ).upper()

            counts[severity] += 1

    return counts


# ---------------------------------------------------------------------
# Runtime — custom checks
# ---------------------------------------------------------------------

def parse_runtime(variant):
    return read_json(
        RESULTS_DIR
        / variant
        / "runtime.json"
    )


# ---------------------------------------------------------------------
# Docker Compose — DCLint
# ---------------------------------------------------------------------

def parse_dclint(variant):
    path = (
        RESULTS_DIR
        / variant
        / "dclint.txt"
    )

    if not path.exists():
        return {
            "available": False,
            "problems": None,
            "errors": None,
            "warnings": None,
        }

    text = path.read_text()

    if "DCLINT_RESULT=PASS" in text:
        return {
            "available": True,
            "problems": 0,
            "errors": 0,
            "warnings": 0,
        }

    # Compatibility with local runs where a clean DCLint
    # execution produced an empty file.
    if not text.strip():
        return {
            "available": True,
            "problems": 0,
            "errors": 0,
            "warnings": 0,
        }

    match = re.search(
        r"(\d+)\s+problems?\s+"
        r"\((\d+)\s+errors?,\s+"
        r"(\d+)\s+warnings?\)",
        text,
    )

    if match:
        return {
            "available": True,
            "problems": int(
                match.group(1)
            ),
            "errors": int(
                match.group(2)
            ),
            "warnings": int(
                match.group(3)
            ),
        }

    return {
        "available": False,
        "problems": None,
        "errors": None,
        "warnings": None,
    }


# ---------------------------------------------------------------------
# Variant analysis
# ---------------------------------------------------------------------

def analyse_variant(variant):
    return {
        "sbom": parse_sbom(
            variant
        ),
        "vulnerabilities": (
            parse_vulnerabilities(
                variant
            )
        ),
        "misconfigurations": (
            parse_misconfigurations(
                variant
            )
        ),
        "runtime": parse_runtime(
            variant
        ),
        "dclint": parse_dclint(
            variant
        ),
    }


# ---------------------------------------------------------------------
# Pipeline gate
# ---------------------------------------------------------------------

def evaluate_gate(result, policy):
    gate_policy = policy["gate"]

    checks = []

    def add_check(
        name,
        passed,
        detail,
    ):
        checks.append({
            "name": name,
            "passed": passed,
            "detail": detail,
        })

    # Application CVEs
    app_policy = gate_policy[
        "application_vulnerabilities"
    ]

    app_results = result[
        "vulnerabilities"
    ]["application"]

    if app_policy.get(
        "require_fix_available",
        False,
    ):
        app_source = app_results[
            "fixable"
        ]

        qualifier = "fixable"
    else:
        app_source = app_results[
            "total"
        ]

        qualifier = "detected"

    blocking_app = sum(
        counter_value(
            app_source,
            severity,
        )
        for severity
        in app_policy["severities"]
    )

    add_check(
        "Application CVEs — Trivy Image",
        blocking_app == 0,
        (
            f"{blocking_app} {qualifier} "
            "blocking findings"
        ),
    )

    # OS CVEs
    os_policy = gate_policy[
        "os_vulnerabilities"
    ]

    os_results = result[
        "vulnerabilities"
    ]["os"]

    if os_policy.get(
        "require_fix_available",
        False,
    ):
        os_source = os_results[
            "fixable"
        ]

        qualifier = "fixable"
    else:
        os_source = os_results[
            "total"
        ]

        qualifier = "detected"

    blocking_os = sum(
        counter_value(
            os_source,
            severity,
        )
        for severity
        in os_policy["severities"]
    )

    add_check(
        "OS CVEs — Trivy Image",
        blocking_os == 0,
        (
            f"{blocking_os} {qualifier} "
            "blocking findings"
        ),
    )

    # Trivy Config
    misconfiguration_policy = (
        gate_policy[
            "misconfigurations"
        ]
    )

    blocking_misconfigs = sum(
        counter_value(
            result[
                "misconfigurations"
            ],
            severity,
        )
        for severity
        in misconfiguration_policy[
            "severities"
        ]
    )

    add_check(
        "Container config — Trivy Config",
        blocking_misconfigs == 0,
        (
            f"{blocking_misconfigs} "
            "blocking misconfigurations"
        ),
    )

    # Runtime
    runtime = result[
        "runtime"
    ]

    runtime_policy = gate_policy[
        "runtime"
    ]

    if runtime_policy.get(
        "require_healthy",
        False,
    ):
        healthy = (
            runtime.get(
                "healthcheck"
            )
            is True
        )

        add_check(
            "Runtime — application health",
            healthy,
            (
                "health endpoint responded correctly"
                if healthy
                else "health validation failed"
            ),
        )

    if runtime_policy.get(
        "forbid_root",
        False,
    ):
        non_root = (
            runtime.get(
                "running_as_root"
            )
            is False
        )

        uid = runtime.get(
            "uid"
        )

        add_check(
            "Runtime — non-root execution",
            non_root,
            (
                f"runtime UID={uid}"
                if uid is not None
                else "runtime UID unavailable"
            ),
        )

    if runtime_policy.get(
        "require_read_only_root_filesystem",
        False,
    ):
        read_only = (
            runtime.get(
                "root_filesystem_writable"
            )
            is False
        )

        add_check(
            "Runtime — read-only root filesystem",
            read_only,
            (
                "write attempt was denied"
                if read_only
                else (
                    "write attempt succeeded "
                    "or result was unavailable"
                )
            ),
        )

    # DCLint
    dclint_policy = gate_policy.get(
        "dclint",
        {
            "max_errors": 0,
            "max_warnings": 0,
        },
    )

    dclint = result[
        "dclint"
    ]

    if not dclint["available"]:
        add_check(
            "Docker Compose — DCLint",
            False,
            "DCLint result unavailable",
        )
    else:
        dclint_ok = (
            dclint["errors"]
            <= dclint_policy[
                "max_errors"
            ]
            and
            dclint["warnings"]
            <= dclint_policy[
                "max_warnings"
            ]
        )

        add_check(
            "Docker Compose — DCLint",
            dclint_ok,
            (
                f"{dclint['errors']} errors, "
                f"{dclint['warnings']} warnings"
            ),
        )

    failures = [
        check
        for check in checks
        if not check[
            "passed"
        ]
    ]

    return {
        "passed": len(
            failures
        ) == 0,
        "checks": checks,
        "failures": failures,
    }


# ---------------------------------------------------------------------
# Terminal report
# ---------------------------------------------------------------------

def print_terminal_report(
    baseline,
    hardened,
    gate_result,
):
    baseline_vulns = baseline[
        "vulnerabilities"
    ]

    hardened_vulns = hardened[
        "vulnerabilities"
    ]

    baseline_app = baseline_vulns[
        "application"
    ]

    hardened_app = hardened_vulns[
        "application"
    ]

    baseline_os = baseline_vulns[
        "os"
    ]

    hardened_os = hardened_vulns[
        "os"
    ]

    baseline_runtime = baseline[
        "runtime"
    ]

    hardened_runtime = hardened[
        "runtime"
    ]

    baseline_dclint = baseline[
        "dclint"
    ]

    hardened_dclint = hardened[
        "dclint"
    ]

    baseline_sbom = baseline[
        "sbom"
    ]["package_entries"]

    hardened_sbom = hardened[
        "sbom"
    ]["package_entries"]

    print()
    print(
        "CONTAINER SECURITY PIPELINE"
    )
    print(
        "=" * 27
    )
    print()

    print(
        f"FINAL RESULT: "
        f"{pass_fail(gate_result['passed'])}"
    )
    print()

    # -------------------------------------------------------------
    # Application
    # -------------------------------------------------------------

    print(
        "APPLICATION DEPENDENCIES — TRIVY IMAGE"
    )
    print(
        "-" * 38
    )

    print(
        "  HIGH + CRITICAL CVEs ............ "
        f"{high_critical(baseline_app['total'])}"
        " -> "
        f"{high_critical(hardened_app['total'])}"
    )

    print(
        "  Fixable HIGH + CRITICAL ......... "
        f"{high_critical(baseline_app['fixable'])}"
        " -> "
        f"{high_critical(hardened_app['fixable'])}"
    )

    print()

    # -------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------

    print(
        "CONTAINER CONFIGURATION"
    )
    print(
        "-" * 23
    )

    print(
        "  Trivy Config HIGH + CRITICAL .... "
        f"{high_critical(baseline['misconfigurations'])}"
        " -> "
        f"{high_critical(hardened['misconfigurations'])}"
    )

    if (
        baseline_dclint["available"]
        and hardened_dclint["available"]
    ):
        print(
            "  DCLint problems ................. "
            f"{baseline_dclint['problems']}"
            " -> "
            f"{hardened_dclint['problems']}"
        )
    else:
        print(
            "  DCLint problems ................. "
            "result unavailable"
        )

    print()

    # -------------------------------------------------------------
    # Runtime
    # -------------------------------------------------------------

    print(
        "RUNTIME VALIDATION — CUSTOM CHECKS"
    )
    print(
        "-" * 34
    )

    print(
        "  Running as root ................. "
        f"{yes_no(baseline_runtime.get('running_as_root'))}"
        " -> "
        f"{yes_no(hardened_runtime.get('running_as_root'))}"
    )

    print(
        "  Root filesystem writable ........ "
        f"{yes_no(baseline_runtime.get('root_filesystem_writable'))}"
        " -> "
        f"{yes_no(hardened_runtime.get('root_filesystem_writable'))}"
    )

    print(
        "  Application healthy ............. "
        f"{yes_no(baseline_runtime.get('healthcheck'))}"
        " -> "
        f"{yes_no(hardened_runtime.get('healthcheck'))}"
    )

    print(
        "  Hardened runtime UID ............ "
        f"{hardened_runtime.get('uid', 'Unknown')}"
    )

    print()

    # -------------------------------------------------------------
    # OS residual/upstream findings
    # -------------------------------------------------------------

    print(
        "REMAINING OS VULNERABILITIES — TRIVY IMAGE"
    )
    print(
        "-" * 43
    )

    for severity in (
        "HIGH",
        "CRITICAL",
    ):
        before = counter_value(
            baseline_os["total"],
            severity,
        )

        after = counter_value(
            hardened_os["total"],
            severity,
        )

        fixable = counter_value(
            hardened_os["fixable"],
            severity,
        )

        no_fix = counter_value(
            hardened_os[
                "no_fix_reported"
            ],
            severity,
        )

        print(
            f"  {severity:<8} "
            f"{before:>3} -> {after:<3} "
            f"(fix available: {fixable}, "
            f"no fix reported: {no_fix})"
        )

    print()

    remaining_fixable = (
        high_critical(
            hardened_os[
                "fixable"
            ]
        )
    )

    remaining_no_fix = (
        high_critical(
            hardened_os[
                "no_fix_reported"
            ]
        )
    )

    print(
        "  Remaining HIGH/CRITICAL:"
    )

    print(
        "    Fix available .................. "
        f"{remaining_fixable}"
    )

    print(
        "    No fixed version reported ...... "
        f"{remaining_no_fix}"
    )

    print()

    if remaining_no_fix:
        print(
            "  Findings without a fixed version "
            "reported by Trivy are retained"
        )

        print(
            "  as upstream residual risk at scan time."
        )

    if remaining_fixable:
        print(
            "  Fixable OS findings outside the "
            "configured blocking policy remain"
        )

        print(
            "  visible and are not silently ignored."
        )

    examples = representative_os_findings(
        hardened_vulns
    )

    if examples:
        print()
        print(
            "  Representative remaining findings:"
        )

        for finding in examples:
            if finding[
                "fixed_version"
            ]:
                remediation = (
                    "fix: "
                    + finding[
                        "fixed_version"
                    ]
                )
            else:
                remediation = (
                    "no fixed version reported"
                )

            print(
                "    "
                f"{finding['id']} | "
                f"{finding['package']} | "
                f"{finding['severity']} | "
                f"{remediation}"
            )

    print()

    # -------------------------------------------------------------
    # SBOM
    # -------------------------------------------------------------

    print(
        "SOFTWARE INVENTORY — SYFT SBOM"
    )
    print(
        "-" * 30
    )

    print(
        "  Package entries ................. "
        f"{baseline_sbom}"
        " -> "
        f"{hardened_sbom}"
    )

    print(
        "  Delta ........................... "
        f"{delta(baseline_sbom, hardened_sbom)}"
    )

    print()

    # -------------------------------------------------------------
    # Gate
    # -------------------------------------------------------------

    print(
        "PIPELINE GATE"
    )
    print(
        "-" * 13
    )

    for check in gate_result[
        "checks"
    ]:
        marker = (
            "PASS"
            if check[
                "passed"
            ]
            else "FAIL"
        )

        print(
            f"  [{marker}] "
            f"{check['name']}"
        )

        print(
            f"         "
            f"{check['detail']}"
        )

    print()

    print(
        f"FINAL RESULT: "
        f"{pass_fail(gate_result['passed'])}"
    )

    if gate_result[
        "passed"
    ]:
        print(
            "All blocking controls passed."
        )
    else:
        print(
            f"{len(gate_result['failures'])} "
            "blocking control(s) failed."
        )

    print()

    print(
        "REPORTS"
    )
    print(
        "-" * 7
    )

    print(
        "  results/comparison.json"
    )

    print(
        "  results/comparison.md"
    )

    print()


# ---------------------------------------------------------------------
# Markdown report — GitHub Job Summary
# ---------------------------------------------------------------------

def generate_markdown(
    baseline,
    hardened,
    gate_result,
):
    baseline_vulns = baseline[
        "vulnerabilities"
    ]

    hardened_vulns = hardened[
        "vulnerabilities"
    ]

    baseline_app = baseline_vulns[
        "application"
    ]

    hardened_app = hardened_vulns[
        "application"
    ]

    baseline_os = baseline_vulns[
        "os"
    ]

    hardened_os = hardened_vulns[
        "os"
    ]

    baseline_runtime = baseline[
        "runtime"
    ]

    hardened_runtime = hardened[
        "runtime"
    ]

    baseline_dclint = baseline[
        "dclint"
    ]

    hardened_dclint = hardened[
        "dclint"
    ]

    final_icon = (
        "✅"
        if gate_result[
            "passed"
        ]
        else "❌"
    )

    final_text = pass_fail(
        gate_result[
            "passed"
        ]
    )

    lines = [
        "# 🛡️ Container Security Pipeline",
        "",
        (
            f"## {final_icon} Pipeline result: "
            f"{final_text}"
        ),
        "",
        "## Remediation summary",
        "",
        "### Application dependencies — Trivy Image",
        "",
        "| Control | Baseline | Hardened |",
        "|---|---:|---:|",
        (
            "| HIGH + CRITICAL CVEs | "
            f"{high_critical(baseline_app['total'])} | "
            f"{high_critical(hardened_app['total'])} |"
        ),
        (
            "| Fixable HIGH + CRITICAL | "
            f"{high_critical(baseline_app['fixable'])} | "
            f"{high_critical(hardened_app['fixable'])} |"
        ),
        "",
        "### Container configuration — Trivy Config + DCLint",
        "",
        "| Control | Baseline | Hardened |",
        "|---|---:|---:|",
        (
            "| Trivy HIGH + CRITICAL misconfigurations | "
            f"{high_critical(baseline['misconfigurations'])} | "
            f"{high_critical(hardened['misconfigurations'])} |"
        ),
    ]

    if (
        baseline_dclint[
            "available"
        ]
        and hardened_dclint[
            "available"
        ]
    ):
        lines.append(
            "| DCLint problems | "
            f"{baseline_dclint['problems']} | "
            f"{hardened_dclint['problems']} |"
        )

    lines.extend([
        "",
        "### Runtime validation — custom checks",
        "",
        "| Control | Baseline | Hardened |",
        "|---|---:|---:|",
        (
            "| Running as root | "
            f"{yes_no(baseline_runtime.get('running_as_root'))} | "
            f"{yes_no(hardened_runtime.get('running_as_root'))} |"
        ),
        (
            "| Root filesystem writable | "
            f"{yes_no(baseline_runtime.get('root_filesystem_writable'))} | "
            f"{yes_no(hardened_runtime.get('root_filesystem_writable'))} |"
        ),
        (
            "| Application healthy | "
            f"{yes_no(baseline_runtime.get('healthcheck'))} | "
            f"{yes_no(hardened_runtime.get('healthcheck'))} |"
        ),
        (
            "| Runtime UID | "
            f"{baseline_runtime.get('uid', 'Unknown')} | "
            f"{hardened_runtime.get('uid', 'Unknown')} |"
        ),
        "",
        "## Remaining OS vulnerabilities — Trivy Image",
        "",
        (
            "These findings come from operating-system packages "
            "inside the container image."
        ),
        "",
        (
            "| Severity | Baseline | Hardened | "
            "Fix available | No fix reported |"
        ),
        "|---|---:|---:|---:|---:|",
    ])

    for severity in (
        "HIGH",
        "CRITICAL",
    ):
        lines.append(
            f"| {severity} | "
            f"{counter_value(baseline_os['total'], severity)} | "
            f"{counter_value(hardened_os['total'], severity)} | "
            f"{counter_value(hardened_os['fixable'], severity)} | "
            f"{counter_value(hardened_os['no_fix_reported'], severity)} |"
        )

    remaining_fixable = high_critical(
        hardened_os[
            "fixable"
        ]
    )

    remaining_no_fix = high_critical(
        hardened_os[
            "no_fix_reported"
        ]
    )

    lines.extend([
        "",
        (
            f"- **Fix available:** "
            f"{remaining_fixable} HIGH/CRITICAL findings."
        ),
        (
            f"- **No fixed version reported by Trivy:** "
            f"{remaining_no_fix} HIGH/CRITICAL findings."
        ),
        "",
        (
            "Findings for which Trivy does not report a fixed "
            "version are retained as **upstream residual risk "
            "at scan time**. The pipeline does not fabricate "
            "or apply unsupported package remediations."
        ),
    ])

    if remaining_fixable:
        lines.extend([
            "",
            (
                "Fixable OS findings that fall outside the "
                "configured blocking policy remain visible "
                "in the evidence and are not silently ignored."
            ),
        ])

    examples = representative_os_findings(
        hardened_vulns
    )

    if examples:
        lines.extend([
            "",
            "### Representative remaining OS findings",
            "",
        ])

        for finding in examples:
            if finding[
                "fixed_version"
            ]:
                remediation = (
                    f"fixed version: "
                    f"`{finding['fixed_version']}`"
                )
            else:
                remediation = (
                    "no fixed version reported"
                )

            lines.append(
                f"- `{finding['id']}` — "
                f"`{finding['package']}` — "
                f"**{finding['severity']}** — "
                f"{remediation}."
            )

    lines.extend([
        "",
        "## Pipeline gate",
        "",
    ])

    for check in gate_result[
        "checks"
    ]:
        icon = (
            "✅"
            if check[
                "passed"
            ]
            else "❌"
        )

        lines.append(
            f"- {icon} "
            f"**{check['name']}** — "
            f"{check['detail']}"
        )

    lines.extend([
        "",
        "## Software inventory — Syft SBOM",
        "",
        (
            f"- Package entries: "
            f"**{baseline['sbom']['package_entries']} "
            f"→ {hardened['sbom']['package_entries']}**"
        ),
        (
            "- Delta: **"
            + delta(
                baseline["sbom"]["package_entries"],
                hardened["sbom"]["package_entries"],
            )
            + "**"
        ),
        "",
        "## Evidence",
        "",
        "- Syft SBOM for baseline and hardened images.",
        "- Trivy Image vulnerability reports retained as JSON.",
        "- Trivy Config reports retained as JSON.",
        "- DCLint Docker Compose validation retained as evidence.",
        "- Runtime validation retained as structured JSON.",
    ])

    return (
        "\n".join(
            lines
        )
        + "\n"
    )


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    policy = yaml.safe_load(
        POLICY_FILE.read_text()
    )

    baseline = analyse_variant(
        BASELINE
    )

    hardened = analyse_variant(
        HARDENED
    )

    gate_result = evaluate_gate(
        hardened,
        policy,
    )

    comparison = {
        "baseline": baseline,
        "hardened": hardened,
        "pipeline_gate": gate_result,
    }

    comparison_json = (
        RESULTS_DIR
        / "comparison.json"
    )

    comparison_markdown = (
        RESULTS_DIR
        / "comparison.md"
    )

    comparison_json.write_text(
        json.dumps(
            comparison,
            indent=2,
            default=dict,
        )
    )

    comparison_markdown.write_text(
        generate_markdown(
            baseline,
            hardened,
            gate_result,
        )
    )

    print_terminal_report(
        baseline,
        hardened,
        gate_result,
    )

    if not gate_result[
        "passed"
    ]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
