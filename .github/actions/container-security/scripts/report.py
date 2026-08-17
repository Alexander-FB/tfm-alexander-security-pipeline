from collections import Counter
from pathlib import Path
import os
import json
import re

import yaml


RESULTS_DIR = Path("results")
POLICY_FILE = Path(os.environ.get("CONTAINER_SECURITY_POLICY", "hardening-policy.yml"))

BASELINE = "baseline"
HARDENED = "hardened"

SEVERITIES = (
    "UNKNOWN",
    "LOW",
    "MEDIUM",
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
    return (
        counter_value(counter, "HIGH")
        + counter_value(counter, "CRITICAL")
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
    difference = after - before

    if difference > 0:
        return f"+{difference}"

    return str(difference)


# ---------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------

def parse_sbom(variant):
    path = (
        RESULTS_DIR
        / variant
        / "sbom.spdx.json"
    )

    data = read_json(path)

    return {
        "package_entries": len(
            data.get("packages", [])
        )
    }


# ---------------------------------------------------------------------
# Trivy vulnerability results
# ---------------------------------------------------------------------

def parse_vulnerabilities(variant):
    path = (
        RESULTS_DIR
        / variant
        / "trivy-image.json"
    )

    data = read_json(path)

    result = {
        "os": {
            "total": Counter(),
            "fixable": Counter(),
        },
        "application": {
            "total": Counter(),
            "fixable": Counter(),
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
                "UNKNOWN"
            ).upper()

            result[
                category
            ]["total"][severity] += 1

            fixed_version = (
                finding.get(
                    "FixedVersion"
                )
                or ""
            ).strip()

            if fixed_version:
                result[
                    category
                ]["fixable"][severity] += 1

    return result


# ---------------------------------------------------------------------
# Trivy configuration results
# ---------------------------------------------------------------------

def parse_misconfigurations(variant):
    path = (
        RESULTS_DIR
        / variant
        / "trivy-config.json"
    )

    data = read_json(path)

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
                "UNKNOWN"
            ).upper()

            counts[severity] += 1

    return counts


# ---------------------------------------------------------------------
# Runtime results
# ---------------------------------------------------------------------

def parse_runtime(variant):
    path = (
        RESULTS_DIR
        / variant
        / "runtime.json"
    )

    return read_json(path)


# ---------------------------------------------------------------------
# DCLint
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

    # Explicit clean result produced by the pipeline.
    if "DCLINT_RESULT=PASS" in text:
        return {
            "available": True,
            "problems": 0,
            "errors": 0,
            "warnings": 0,
        }

    # When findings exist, DCLint prints its normal summary.
    match = re.search(
        r"(\d+)\s+problems?\s+"
        r"\((\d+)\s+errors?,\s+"
        r"(\d+)\s+warnings?\)",
        text,
    )

    if match:
        return {
            "available": True,
            "problems": int(match.group(1)),
            "errors": int(match.group(2)),
            "warnings": int(match.group(3)),
        }

    # FAIL without a parsable DCLint report means the tool itself
    # did not complete correctly. Fail closed.
    return {
        "available": False,
        "problems": None,
        "errors": None,
        "warnings": None,
    }


# ---------------------------------------------------------------------
# Complete variant analysis
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

    def add_check(name, passed, detail):
        checks.append({
            "name": name,
            "passed": passed,
            "detail": detail,
        })

    # -------------------------------------------------------------
    # Application vulnerabilities
    # -------------------------------------------------------------

    app_policy = gate_policy[
        "application_vulnerabilities"
    ]

    app_results = result[
        "vulnerabilities"
    ]["application"]

    if app_policy.get(
        "require_fix_available",
        False
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
            severity
        )
        for severity
        in app_policy["severities"]
    )

    add_check(
        "Application vulnerability policy",
        blocking_app == 0,
        (
            f"{blocking_app} {qualifier} "
            "blocking vulnerability findings"
        ),
    )

    # -------------------------------------------------------------
    # Operating-system vulnerabilities
    # -------------------------------------------------------------

    os_policy = gate_policy[
        "os_vulnerabilities"
    ]

    os_results = result[
        "vulnerabilities"
    ]["os"]

    if os_policy.get(
        "require_fix_available",
        False
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
            severity
        )
        for severity
        in os_policy["severities"]
    )

    add_check(
        "Operating-system vulnerability policy",
        blocking_os == 0,
        (
            f"{blocking_os} {qualifier} "
            "blocking vulnerability findings"
        ),
    )

    # -------------------------------------------------------------
    # Trivy configuration
    # -------------------------------------------------------------

    misconfiguration_policy = (
        gate_policy[
            "misconfigurations"
        ]
    )

    blocking_misconfigs = sum(
        counter_value(
            result["misconfigurations"],
            severity
        )
        for severity
        in misconfiguration_policy[
            "severities"
        ]
    )

    add_check(
        "Trivy configuration policy",
        blocking_misconfigs == 0,
        (
            f"{blocking_misconfigs} "
            "blocking misconfigurations"
        ),
    )

    # -------------------------------------------------------------
    # Runtime
    # -------------------------------------------------------------

    runtime = result["runtime"]

    runtime_policy = gate_policy[
        "runtime"
    ]

    if runtime_policy.get(
        "require_healthy",
        False
    ):
        healthy = (
            runtime.get(
                "healthcheck"
            )
            is True
        )

        add_check(
            "Application health",
            healthy,
            (
                "health endpoint responded correctly"
                if healthy
                else "health validation failed"
            ),
        )

    if runtime_policy.get(
        "forbid_root",
        False
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
            "Non-root execution",
            non_root,
            (
                f"runtime UID={uid}"
                if uid is not None
                else "runtime UID unavailable"
            ),
        )

    if runtime_policy.get(
        "require_read_only_root_filesystem",
        False
    ):
        read_only = (
            runtime.get(
                "root_filesystem_writable"
            )
            is False
        )

        add_check(
            "Read-only root filesystem",
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

    # -------------------------------------------------------------
    # DCLint
    # -------------------------------------------------------------

    dclint_policy = gate_policy.get(
        "dclint",
        {
            "max_errors": 0,
            "max_warnings": 0,
        },
    )

    dclint = result["dclint"]

    if not dclint["available"]:
        add_check(
            "Docker Compose lint",
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
            "Docker Compose lint",
            dclint_ok,
            (
                f"{dclint['errors']} errors, "
                f"{dclint['warnings']} warnings"
            ),
        )

    failures = [
        check
        for check in checks
        if not check["passed"]
    ]

    return {
        "passed": len(failures) == 0,
        "checks": checks,
        "failures": failures,
    }


# ---------------------------------------------------------------------
# Terminal output
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

    baseline_os = baseline_vulns[
        "os"
    ]

    hardened_os = hardened_vulns[
        "os"
    ]

    baseline_app = baseline_vulns[
        "application"
    ]

    hardened_app = hardened_vulns[
        "application"
    ]

    baseline_misconfig = baseline[
        "misconfigurations"
    ]

    hardened_misconfig = hardened[
        "misconfigurations"
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

    app_before = high_critical(
        baseline_app["total"]
    )

    app_after = high_critical(
        hardened_app["total"]
    )

    app_fixable_before = high_critical(
        baseline_app["fixable"]
    )

    app_fixable_after = high_critical(
        hardened_app["fixable"]
    )

    misconfig_before = high_critical(
        baseline_misconfig
    )

    misconfig_after = high_critical(
        hardened_misconfig
    )

    os_high_before = counter_value(
        baseline_os["total"],
        "HIGH"
    )

    os_high_after = counter_value(
        hardened_os["total"],
        "HIGH"
    )

    os_critical_before = counter_value(
        baseline_os["total"],
        "CRITICAL"
    )

    os_critical_after = counter_value(
        hardened_os["total"],
        "CRITICAL"
    )

    os_total_before = (
        os_high_before
        + os_critical_before
    )

    os_total_after = (
        os_high_after
        + os_critical_after
    )

    os_fixable_critical_after = (
        counter_value(
            hardened_os["fixable"],
            "CRITICAL"
        )
    )

    print()
    print(
        "CONTAINER SECURITY PIPELINE"
    )
    print(
        "=" * 27
    )
    print()

    print(
        "FINAL RESULT: "
        f"{pass_fail(gate_result['passed'])}"
    )

    print()

    # -------------------------------------------------------------
    # Remediation summary
    # -------------------------------------------------------------

    print(
        "REMEDIATION SUMMARY"
    )
    print(
        "-" * 19
    )

    print(
        "Application vulnerabilities:"
    )

    print(
        "  HIGH + CRITICAL ................. "
        f"{app_before} -> {app_after}"
    )

    print(
        "  Fixable HIGH + CRITICAL ......... "
        f"{app_fixable_before} -> "
        f"{app_fixable_after}"
    )

    print()

    print(
        "Container configuration:"
    )

    print(
        "  Trivy HIGH + CRITICAL ........... "
        f"{misconfig_before} -> "
        f"{misconfig_after}"
    )

    if (
        baseline_dclint["available"]
        and hardened_dclint["available"]
    ):
        print(
            "  DCLint problems ................. "
            f"{baseline_dclint['problems']} -> "
            f"{hardened_dclint['problems']}"
        )
    else:
        print(
            "  DCLint problems ................. "
            "result unavailable"
        )

    print()

    print(
        "Runtime security:"
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
    # Residual risk
    # -------------------------------------------------------------

    print(
        "RESIDUAL RISK"
    )
    print(
        "-" * 13
    )

    print(
        "Operating-system vulnerabilities:"
    )

    print(
        "  HIGH ............................ "
        f"{os_high_before} -> {os_high_after}"
    )

    print(
        "  CRITICAL ........................ "
        f"{os_critical_before} -> "
        f"{os_critical_after}"
    )

    print(
        "  HIGH + CRITICAL total ........... "
        f"{os_total_before} -> "
        f"{os_total_after}"
    )

    print(
        "  Fixable CRITICAL after hardening  "
        f"{os_fixable_critical_after}"
    )

    print()

    print(
        "  Remaining non-blocking OS findings "
        "are retained as residual risk."
    )

    print()

    # -------------------------------------------------------------
    # Inventory
    # -------------------------------------------------------------

    print(
        "SOFTWARE INVENTORY"
    )
    print(
        "-" * 18
    )

    print(
        "  SBOM package entries ............ "
        f"{baseline_sbom} -> {hardened_sbom}"
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
            if check["passed"]
            else "FAIL"
        )

        print(
            f"  [{marker}] {check['name']}"
        )

        print(
            f"         {check['detail']}"
        )

    print()

    if gate_result["passed"]:
        print(
            "FINAL RESULT: PASS"
        )
        print(
            "All blocking controls passed."
        )
    else:
        print(
            "FINAL RESULT: FAIL"
        )
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
# Markdown output for GitHub Actions
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

    baseline_misconfig = baseline[
        "misconfigurations"
    ]

    hardened_misconfig = hardened[
        "misconfigurations"
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
        if gate_result["passed"]
        else "❌"
    )

    final_text = (
        "PASS"
        if gate_result["passed"]
        else "FAIL"
    )

    lines = [
        "# 🛡️ Container Security Pipeline",
        "",
        (
            f"## {final_icon} Pipeline result: "
            f"{final_text}"
        ),
        "",
        "### Remediation summary",
        "",
        "| Control | Baseline | Hardened | Evolution |",
        "|---|---:|---:|---|",
        (
            "| Application HIGH + CRITICAL CVEs | "
            f"{high_critical(baseline_app['total'])} | "
            f"{high_critical(hardened_app['total'])} | "
            f"{high_critical(baseline_app['total'])} → "
            f"{high_critical(hardened_app['total'])} |"
        ),
        (
            "| Fixable application HIGH + CRITICAL | "
            f"{high_critical(baseline_app['fixable'])} | "
            f"{high_critical(hardened_app['fixable'])} | "
            f"{high_critical(baseline_app['fixable'])} → "
            f"{high_critical(hardened_app['fixable'])} |"
        ),
        (
            "| Trivy HIGH + CRITICAL misconfigurations | "
            f"{high_critical(baseline_misconfig)} | "
            f"{high_critical(hardened_misconfig)} | "
            f"{high_critical(baseline_misconfig)} → "
            f"{high_critical(hardened_misconfig)} |"
        ),
    ]

    if (
        baseline_dclint["available"]
        and hardened_dclint["available"]
    ):
        lines.append(
            "| DCLint problems | "
            f"{baseline_dclint['problems']} | "
            f"{hardened_dclint['problems']} | "
            f"{baseline_dclint['problems']} → "
            f"{hardened_dclint['problems']} |"
        )

    lines.extend([
        (
            "| Running as root | "
            f"{yes_no(baseline_runtime.get('running_as_root'))} | "
            f"{yes_no(hardened_runtime.get('running_as_root'))} | "
            "Hardened |"
        ),
        (
            "| Root filesystem writable | "
            f"{yes_no(baseline_runtime.get('root_filesystem_writable'))} | "
            f"{yes_no(hardened_runtime.get('root_filesystem_writable'))} | "
            "Hardened |"
        ),
        (
            "| Application healthy | "
            f"{yes_no(baseline_runtime.get('healthcheck'))} | "
            f"{yes_no(hardened_runtime.get('healthcheck'))} | "
            "Preserved |"
        ),
        "",
        "### Pipeline gate",
        "",
    ])

    for check in gate_result[
        "checks"
    ]:
        icon = (
            "✅"
            if check["passed"]
            else "❌"
        )

        lines.append(
            f"- {icon} **{check['name']}** — "
            f"{check['detail']}"
        )

    lines.extend([
        "",
        "### Residual risk",
        "",
        "| OS severity | Baseline | Hardened |",
        "|---|---:|---:|",
        (
            "| HIGH | "
            f"{counter_value(baseline_os['total'], 'HIGH')} | "
            f"{counter_value(hardened_os['total'], 'HIGH')} |"
        ),
        (
            "| CRITICAL | "
            f"{counter_value(baseline_os['total'], 'CRITICAL')} | "
            f"{counter_value(hardened_os['total'], 'CRITICAL')} |"
        ),
        (
            "| HIGH + CRITICAL | "
            f"{high_critical(baseline_os['total'])} | "
            f"{high_critical(hardened_os['total'])} |"
        ),
        "",
        (
            "Remaining operating-system findings are retained "
            "in the audit evidence as residual risk. "
            "The pipeline blocks only findings that violate "
            "the configured gate policy."
        ),
        "",
        "### Software inventory",
        "",
        (
            f"- SBOM package entries: "
            f"**{baseline['sbom']['package_entries']} → "
            f"{hardened['sbom']['package_entries']}**"
        ),
        (
            f"- Hardened runtime UID: "
            f"**{hardened_runtime.get('uid', 'Unknown')}**"
        ),
        "",
        "### Evidence",
        "",
        "- Syft SBOM generated for baseline and hardened images.",
        "- Trivy image vulnerability reports retained as JSON.",
        "- Trivy configuration reports retained as JSON.",
        "- DCLint output retained for Docker Compose validation.",
        "- Runtime validation retained as structured JSON.",
    ])

    return (
        "\n".join(lines)
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
        policy
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

    if not gate_result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
