import argparse
import json
import subprocess
import urllib.request
from pathlib import Path


def run(command):
    return subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True
    )


def check_health():
    try:
        with urllib.request.urlopen(
            "http://localhost:8080/health",
            timeout=5
        ) as response:
            return response.status == 200
    except Exception:
        return False


def check_user():
    result = run("docker compose exec -T api id -u")

    if result.returncode != 0:
        return {
            "uid": None,
            "running_as_root": None
        }

    uid = int(result.stdout.strip())

    return {
        "uid": uid,
        "running_as_root": uid == 0
    }


def check_root_filesystem():
    result = run(
        "docker compose exec -T api "
        "sh -c 'touch /runtime-security-test'"
    )

    writable = result.returncode == 0

    if writable:
        run(
            "docker compose exec -T api "
            "rm -f /runtime-security-test"
        )

    return {
        "root_filesystem_writable": writable
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--variant",
        choices=["baseline", "hardened"],
        required=True
    )
    args = parser.parse_args()

    result_file = Path("results") / args.variant / "runtime.json"
    result_file.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "variant": args.variant,
        "healthcheck": check_health(),
        **check_user(),
        **check_root_filesystem(),
    }

    result_file.write_text(
        json.dumps(result, indent=2)
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
