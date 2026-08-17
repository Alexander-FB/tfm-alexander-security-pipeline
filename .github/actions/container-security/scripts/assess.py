from pathlib import Path
import os

import yaml

from report import (
    analyse_variant,
    evaluate_gate,
)


POLICY_FILE = Path(
    os.environ.get(
        "CONTAINER_SECURITY_POLICY",
        "container-security-policy.yml",
    )
)

COMPOSE_FILE = Path(
    "docker-compose.yml"
)


def read_nginx_image():
    compose = yaml.safe_load(
        COMPOSE_FILE.read_text(
            encoding="utf-8"
        )
    )

    return (
        compose
        .get("services", {})
        .get("nginx", {})
        .get("image")
    )


def main():
    policy = yaml.safe_load(
        POLICY_FILE.read_text(
            encoding="utf-8"
        )
    )

    baseline = analyse_variant(
        "baseline"
    )

    gate_result = evaluate_gate(
        baseline,
        policy,
    )

    approved_nginx = (
        policy
        .get("images", {})
        .get("nginx")
    )

    current_nginx = (
        read_nginx_image()
    )

    nginx_compliant = (
        approved_nginx is not None
        and current_nginx
        == approved_nginx
    )

    remediation_required = (
        not gate_result["passed"]
        or not nginx_compliant
    )

    value = (
        "true"
        if remediation_required
        else "false"
    )

    print()
    print(
        "BASELINE COMPLIANCE"
    )
    print(
        "-------------------"
    )

    print(
        "Security controls ......... "
        + (
            "PASS"
            if gate_result["passed"]
            else "FAIL"
        )
    )

    print(
        "Nginx image ............... "
        + (
            "PASS"
            if nginx_compliant
            else "FAIL"
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

    if not gate_result["passed"]:
        print(
            "Blocking security controls:"
        )

        for check in gate_result[
            "failures"
        ]:
            print(
                f"  - {check['name']}: "
                f"{check['detail']}"
            )

    if not nginx_compliant:
        print()
        print(
            "Nginx image policy:"
        )

        print(
            f"  Current:  "
            f"{current_nginx}"
        )

        print(
            f"  Approved: "
            f"{approved_nginx}"
        )

    if not remediation_required:
        print()
        print(
            "Baseline already satisfies "
            "the central security policy."
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
