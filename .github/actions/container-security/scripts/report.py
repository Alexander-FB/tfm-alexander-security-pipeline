from collections import Counter
from html import escape
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
    with path.open(encoding="utf-8") as file:
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


def html(value):
    return escape(
        str(value),
        quote=False,
    )


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
            data.get(
                "packages",
                [],
            )
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

    for scan_result in data.get(
        "Results",
        [],
    ):
        scan_class = scan_result.get(
            "Class",
            "",
        )

        scan_type = scan_result.get(
            "Type",
            "",
        )

        if (
            scan_class == "os-pkgs"
            or scan_type in os_types
        ):
            category = "os"
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
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNKNOWN": 4,
    }

    findings = [
        finding
        for finding
        in vulnerability_data[
            "os"
        ]["findings"]
        if finding["severity"]
        in BLOCKING_SEVERITIES
    ]

    findings.sort(
        key=lambda finding: (
            0
            if not finding[
                "fixed_version"
            ]
            else 1,
            severity_order.get(
                finding[
                    "severity"
                ],
                99,
            ),
            finding["id"],
            finding["package"],
        )
    )

    unique = []
    seen_ids = set()

    for finding in findings:
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

    for scan_result in data.get(
        "Results",
        [],
    ):
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

            counts[
                severity
            ] += 1

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

    text = path.read_text(
        encoding="utf-8"
    )

    if (
        "DCLINT_RESULT=PASS"
        in text
        or not text.strip()
    ):
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

def evaluate_gate(
    result,
    policy,
):
    gate_policy = policy[
        "gate"
    ]

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

    # Application vulnerabilities

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

        app_qualifier = (
            "fixable"
        )
    else:
        app_source = app_results[
            "total"
        ]

        app_qualifier = (
            "detected"
        )

    blocking_app = sum(
        counter_value(
            app_source,
            severity,
        )
        for severity
        in app_policy[
            "severities"
        ]
    )

    add_check(
        "Application CVEs — Trivy Image",
        blocking_app == 0,
        (
            f"{blocking_app} "
            f"{app_qualifier} "
            "blocking findings"
        ),
    )

    # Operating-system vulnerabilities

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

        os_qualifier = (
            "fixable"
        )
    else:
        os_source = os_results[
            "total"
        ]

        os_qualifier = (
            "detected"
        )

    blocking_os = sum(
        counter_value(
            os_source,
            severity,
        )
        for severity
        in os_policy[
            "severities"
        ]
    )

    add_check(
        "OS CVEs — Trivy Image",
        blocking_os == 0,
        (
            f"{blocking_os} "
            f"{os_qualifier} "
            "blocking findings"
        ),
    )

    # Trivy configuration

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

    # Runtime validation

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

    # Docker Compose lint

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

    if not dclint[
        "available"
    ]:
        add_check(
            "Docker Compose — DCLint",
            False,
            "DCLint result unavailable",
        )
    else:
        dclint_ok = (
            dclint[
                "errors"
            ]
            <= dclint_policy[
                "max_errors"
            ]
            and
            dclint[
                "warnings"
            ]
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
        "passed": not failures,
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
    baseline_app = baseline[
        "vulnerabilities"
    ]["application"]

    hardened_app = hardened[
        "vulnerabilities"
    ]["application"]

    baseline_os = baseline[
        "vulnerabilities"
    ]["os"]

    hardened_os = hardened[
        "vulnerabilities"
    ]["os"]

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
        "==========================="
    )
    print()

    print(
        f"FINAL RESULT: "
        f"{pass_fail(gate_result['passed'])}"
    )
    print()

    print(
        "APPLICATION DEPENDENCIES — TRIVY IMAGE"
    )
    print(
        "--------------------------------------"
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

    print(
        "CONTAINER CONFIGURATION"
    )
    print(
        "-----------------------"
    )

    print(
        "  Trivy Config HIGH + CRITICAL .... "
        f"{high_critical(baseline['misconfigurations'])}"
        " -> "
        f"{high_critical(hardened['misconfigurations'])}"
    )

    if (
        baseline_dclint[
            "available"
        ]
        and hardened_dclint[
            "available"
        ]
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

    print(
        "RUNTIME VALIDATION — CUSTOM CHECKS"
    )
    print(
        "----------------------------------"
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
        "  Final runtime UID ............... "
        f"{hardened_runtime.get('uid', 'Unknown')}"
    )

    print()

    print(
        "REMAINING OS VULNERABILITIES — TRIVY IMAGE"
    )
    print(
        "-------------------------------------------"
    )

    for severity in (
        "HIGH",
        "CRITICAL",
    ):
        before = counter_value(
            baseline_os[
                "total"
            ],
            severity,
        )

        after = counter_value(
            hardened_os[
                "total"
            ],
            severity,
        )

        fixable = counter_value(
            hardened_os[
                "fixable"
            ],
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

    print(
        "SOFTWARE INVENTORY — SYFT SBOM"
    )
    print(
        "------------------------------"
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

    print(
        "PIPELINE GATE"
    )
    print(
        "-------------"
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


# ---------------------------------------------------------------------
# GitHub Job Summary helpers
# ---------------------------------------------------------------------

def render_html_table(
    headers,
    rows,
):
    lines = [
        "<table>",
        "<thead>",
        "<tr>",
    ]

    for header in headers:
        lines.append(
            f"<th>{html(header)}</th>"
        )

    lines.extend([
        "</tr>",
        "</thead>",
        "<tbody>",
    ])

    for row in rows:
        lines.append(
            "<tr>"
        )

        for cell in row:
            lines.append(
                f"<td>{html(cell)}</td>"
            )

        lines.append(
            "</tr>"
        )

    lines.extend([
        "</tbody>",
        "</table>",
    ])

    return "\n".join(
        lines
    )


def render_summary_card(
    title,
    table_html,
):
    return (
        f"<strong>{html(title)}</strong>"
        "<br/>\n"
        f"{table_html}"
    )


def effective_remediation_applied(
    baseline,
    hardened,
):
    baseline_app = baseline[
        "vulnerabilities"
    ]["application"]

    hardened_app = hardened[
        "vulnerabilities"
    ]["application"]

    comparisons = [
        (
            high_critical(
                baseline_app[
                    "total"
                ]
            ),
            high_critical(
                hardened_app[
                    "total"
                ]
            ),
        ),
        (
            high_critical(
                baseline_app[
                    "fixable"
                ]
            ),
            high_critical(
                hardened_app[
                    "fixable"
                ]
            ),
        ),
        (
            high_critical(
                baseline[
                    "misconfigurations"
                ]
            ),
            high_critical(
                hardened[
                    "misconfigurations"
                ]
            ),
        ),
        (
            baseline[
                "runtime"
            ].get(
                "running_as_root"
            ),
            hardened[
                "runtime"
            ].get(
                "running_as_root"
            ),
        ),
        (
            baseline[
                "runtime"
            ].get(
                "root_filesystem_writable"
            ),
            hardened[
                "runtime"
            ].get(
                "root_filesystem_writable"
            ),
        ),
        (
            baseline[
                "runtime"
            ].get(
                "healthcheck"
            ),
            hardened[
                "runtime"
            ].get(
                "healthcheck"
            ),
        ),
        (
            baseline[
                "runtime"
            ].get(
                "uid"
            ),
            hardened[
                "runtime"
            ].get(
                "uid"
            ),
        ),
        (
            baseline[
                "sbom"
            ][
                "package_entries"
            ],
            hardened[
                "sbom"
            ][
                "package_entries"
            ],
        ),
    ]

    if (
        baseline[
            "dclint"
        ][
            "available"
        ]
        and hardened[
            "dclint"
        ][
            "available"
        ]
    ):
        comparisons.append(
            (
                baseline[
                    "dclint"
                ][
                    "problems"
                ],
                hardened[
                    "dclint"
                ][
                    "problems"
                ],
            )
        )

    return any(
        before != after
        for before, after
        in comparisons
    )


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

    baseline_sbom = baseline[
        "sbom"
    ][
        "package_entries"
    ]

    hardened_sbom = hardened[
        "sbom"
    ][
        "package_entries"
    ]

    baseline_app_hc = high_critical(
        baseline_app[
            "total"
        ]
    )

    hardened_app_hc = high_critical(
        hardened_app[
            "total"
        ]
    )

    baseline_app_fixable = high_critical(
        baseline_app[
            "fixable"
        ]
    )

    hardened_app_fixable = high_critical(
        hardened_app[
            "fixable"
        ]
    )

    baseline_misconfigs = high_critical(
        baseline[
            "misconfigurations"
        ]
    )

    hardened_misconfigs = high_critical(
        hardened[
            "misconfigurations"
        ]
    )

    baseline_dclint_problems = (
        baseline_dclint[
            "problems"
        ]
        if baseline_dclint[
            "available"
        ]
        else "n/a"
    )

    hardened_dclint_problems = (
        hardened_dclint[
            "problems"
        ]
        if hardened_dclint[
            "available"
        ]
        else "n/a"
    )

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

    remediation_applied = (
        effective_remediation_applied(
            baseline,
            hardened,
        )
    )

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

    # -------------------------------------------------------------
    # Pipeline path
    # -------------------------------------------------------------

    if remediation_applied:
        assessment_title = (
            "Remediation summary"
        )

        pipeline_path = (
            "Baseline audit → "
            "Apply hardening → "
            "Hardened validation → "
            "Security gate"
        )

        assessment_text = (
            "Automated remediation changed the received "
            "configuration. The hardened state was re-scanned "
            "and validated against the central security policy."
        )
    else:
        assessment_title = (
            "Security assessment"
        )

        pipeline_path = (
            "Baseline audit → "
            "Security gate"
        )

        assessment_text = (
            "The final application state satisfies "
            "the configured security policy."
        )
    # -------------------------------------------------------------
    # 2x2 security overview
    # -------------------------------------------------------------

    app_table = render_html_table(
        [
            "Control",
            "Baseline",
            "Final",
        ],
        [
            [
                "HIGH + CRITICAL CVEs",
                baseline_app_hc,
                hardened_app_hc,
            ],
            [
                "Fixable HIGH + CRITICAL",
                baseline_app_fixable,
                hardened_app_fixable,
            ],
        ],
    )

    config_table = render_html_table(
        [
            "Control",
            "Baseline",
            "Final",
        ],
        [
            [
                "Trivy HIGH + CRITICAL misconfigurations",
                baseline_misconfigs,
                hardened_misconfigs,
            ],
            [
                "DCLint problems",
                baseline_dclint_problems,
                hardened_dclint_problems,
            ],
        ],
    )

    runtime_table = render_html_table(
        [
            "Control",
            "Baseline",
            "Final",
        ],
        [
            [
                "Running as root",
                yes_no(
                    baseline_runtime.get(
                        "running_as_root"
                    )
                ),
                yes_no(
                    hardened_runtime.get(
                        "running_as_root"
                    )
                ),
            ],
            [
                "Root filesystem writable",
                yes_no(
                    baseline_runtime.get(
                        "root_filesystem_writable"
                    )
                ),
                yes_no(
                    hardened_runtime.get(
                        "root_filesystem_writable"
                    )
                ),
            ],
            [
                "Application healthy",
                yes_no(
                    baseline_runtime.get(
                        "healthcheck"
                    )
                ),
                yes_no(
                    hardened_runtime.get(
                        "healthcheck"
                    )
                ),
            ],
            [
                "Runtime UID",
                baseline_runtime.get(
                    "uid",
                    "Unknown",
                ),
                hardened_runtime.get(
                    "uid",
                    "Unknown",
                ),
            ],
        ],
    )

    os_table = render_html_table(
        [
            "Severity",
            "Baseline",
            "Final",
            "Fix available",
            "No fix reported",
        ],
        [
            [
                "HIGH",
                counter_value(
                    baseline_os[
                        "total"
                    ],
                    "HIGH",
                ),
                counter_value(
                    hardened_os[
                        "total"
                    ],
                    "HIGH",
                ),
                counter_value(
                    hardened_os[
                        "fixable"
                    ],
                    "HIGH",
                ),
                counter_value(
                    hardened_os[
                        "no_fix_reported"
                    ],
                    "HIGH",
                ),
            ],
            [
                "CRITICAL",
                counter_value(
                    baseline_os[
                        "total"
                    ],
                    "CRITICAL",
                ),
                counter_value(
                    hardened_os[
                        "total"
                    ],
                    "CRITICAL",
                ),
                counter_value(
                    hardened_os[
                        "fixable"
                    ],
                    "CRITICAL",
                ),
                counter_value(
                    hardened_os[
                        "no_fix_reported"
                    ],
                    "CRITICAL",
                ),
            ],
        ],
    )

    overview_grid = "\n".join([
        '<table width="100%">',
        "<tbody>",

        "<tr>",

        '<td width="50%" valign="top">',
        render_summary_card(
            "Application dependencies — Trivy Image",
            app_table,
        ),
        "</td>",

        '<td width="50%" valign="top">',
        render_summary_card(
            "Container configuration — Trivy Config + DCLint",
            config_table,
        ),
        "</td>",

        "</tr>",

        "<tr>",

        '<td width="50%" valign="top">',
        render_summary_card(
            "Runtime validation — custom checks",
            runtime_table,
        ),
        "</td>",

        '<td width="50%" valign="top">',
        render_summary_card(
            "OS vulnerabilities — Trivy Image",
            os_table,
        ),
        "</td>",

        "</tr>",

        "</tbody>",
        "</table>",
    ])

    # -------------------------------------------------------------
    # Gate
    # -------------------------------------------------------------

    gate_rows = []

    for check in gate_result[
        "checks"
    ]:
        gate_rows.append([
            (
                "✅"
                if check[
                    "passed"
                ]
                else "❌"
            ),
            check[
                "name"
            ],
            check[
                "detail"
            ],
        ])

    gate_table = render_html_table(
        [
            "Status",
            "Control",
            "Result",
        ],
        gate_rows,
    )

    # -------------------------------------------------------------
    # Inventory
    # -------------------------------------------------------------

    inventory_table = render_html_table(
        [
            "Source",
            "Metric",
            "Baseline",
            "Final",
        ],
        [
            [
                "Syft SBOM",
                "Package entries",
                baseline_sbom,
                hardened_sbom,
            ],
        ],
    )

    # -------------------------------------------------------------
    # Residual risk details
    # -------------------------------------------------------------

    examples = representative_os_findings(
        hardened_vulns
    )

    residual_lines = [
        "<details>",
        (
            "<summary><strong>"
            "Residual-risk details"
            "</strong></summary>"
        ),
        "<br/>",
        (
            "<p>"
            f"<strong>{remaining_fixable}</strong> "
            "HIGH/CRITICAL OS findings have a fixed version "
            "reported by Trivy but do not match the configured "
            "blocking policy. "
            f"<strong>{remaining_no_fix}</strong> "
            "HIGH/CRITICAL OS findings have no fixed version "
            "reported and are retained as upstream residual "
            "risk at scan time."
            "</p>"
        ),
    ]

    if examples:
        residual_lines.extend([
            (
                "<p><strong>"
                "Representative findings"
                "</strong></p>"
            ),
            "<ul>",
        ])

        for finding in examples:
            if finding[
                "fixed_version"
            ]:
                remediation = (
                    "fixed version: "
                    f"<code>"
                    f"{html(finding['fixed_version'])}"
                    f"</code>"
                )
            else:
                remediation = (
                    "no fixed version reported"
                )

            residual_lines.append(
                "<li>"
                f"<code>{html(finding['id'])}</code>"
                " — "
                f"<code>{html(finding['package'])}</code>"
                " — "
                f"<strong>{html(finding['severity'])}</strong>"
                " — "
                f"{remediation}"
                "</li>"
            )

        residual_lines.append(
            "</ul>"
        )

    residual_lines.append(
        "</details>"
    )

    residual_details = "\n".join(
        residual_lines
    )

    # -------------------------------------------------------------
    # Evidence
    # -------------------------------------------------------------

    evidence_details = "\n".join([
        "<details>",
        (
            "<summary><strong>"
            "Evidence retained"
            "</strong></summary>"
        ),
        "<br/>",
        "<ul>",
        (
            "<li>"
            "Syft SBOM for baseline and final state."
            "</li>"
        ),
        (
            "<li>"
            "Trivy Image vulnerability reports retained as JSON."
            "</li>"
        ),
        (
            "<li>"
            "Trivy Config reports retained as JSON."
            "</li>"
        ),
        (
            "<li>"
            "DCLint Docker Compose validation retained as evidence."
            "</li>"
        ),
        (
            "<li>"
            "Runtime validation retained as structured JSON."
            "</li>"
        ),
        (
            "<li>"
            "Consolidated outputs: "
            "<code>results/comparison.json</code> and "
            "<code>results/comparison.md</code>."
            "</li>"
        ),
        "</ul>",
        "</details>",
    ])

    # -------------------------------------------------------------
    # Final document
    # -------------------------------------------------------------

    lines = [
        "# 🛡️ Container Security Pipeline",
        "",
        (
            f"## {final_icon} "
            f"Pipeline result: {final_text}"
        ),
        "",
        f"## {assessment_title}",
        "",
        (
            f"> {assessment_text}"
        ),
        "",
        overview_grid,
        "",
        "### Residual-risk interpretation",
        "",
        (
            f"- **{remaining_fixable}** HIGH/CRITICAL "
            "OS findings have a fix reported by Trivy "
            "but fall outside the configured blocking policy."
        ),
        (
            f"- **{remaining_no_fix}** HIGH/CRITICAL "
            "OS findings have no fixed version reported "
            "and are retained as upstream residual risk."
        ),
        "",
        residual_details,
        "",
        "## Pipeline gate",
        "",
        gate_table,
        "",
        "## Software inventory",
        "",
        inventory_table,
        "",
        evidence_details,
    ]

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
        POLICY_FILE.read_text(
            encoding="utf-8"
        )
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

    (
        RESULTS_DIR
        / "comparison.json"
    ).write_text(
        json.dumps(
            comparison,
            indent=2,
            default=dict,
        ),
        encoding="utf-8",
    )

    (
        RESULTS_DIR
        / "comparison.md"
    ).write_text(
        generate_markdown(
            baseline,
            hardened,
            gate_result,
        ),
        encoding="utf-8",
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
