from pathlib import Path
import os

import yaml

from report import analyse_variant, evaluate_gate


POLICY_FILE = Path(
    os.environ.get(
        "CONTAINER_SECURITY_POLICY",
        "hardening-policy.yml",
    )
)


def main():
    policy = yaml.safe_load(
        POLICY_FILE.read_text()
    )

    baseline = analyse_variant(
        "baseline"
    )

    result = evaluate_gate(
        baseline,
        policy,
    )

    remediation_required = (
        not result["passed"]
    )

    value = (
        "true"
        if remediation_required
        else "false"
    )

    print()
    print("BASELINE COMPLIANCE")
    print("-------------------")
    print(
        "Compliant ................. "
        + (
            "No"
            if remediation_required
            else "Yes"
        )
    )
    print(
        "Remediation required ...... "
        + (
            "Yes"
            if remediation_required
            else "No"
        )
    )
    print()

    if remediation_required:
        print("Blocking controls:")
        for check in result["failures"]:
            print(
                f"  - {check['name']}: "
                f"{check['detail']}"
            )
    else:
        print(
            "Baseline already satisfies "
            "the configured security policy."
        )

    github_output = os.environ.get(
        "GITHUB_OUTPUT"
    )

    if github_output:
        with open(
            github_output,
            "a",
            encoding="utf-8",
        ) as output:
            output.write(
                "remediation_required="
                f"{value}\n"
            )


if __name__ == "__main__":
    main()
