from pathlib import Path
import os

import yaml


COMPOSE_FILE = Path("docker-compose.yml")

POLICY_FILE = Path(
    os.environ.get(
        "CONTAINER_SECURITY_POLICY",
        "container-security-policy.yml",
    )
)


def main():
    policy = yaml.safe_load(
        POLICY_FILE.read_text(
            encoding="utf-8"
        )
    )

    approved_image = (
        policy
        .get("images", {})
        .get("nginx")
    )

    if not approved_image:
        raise RuntimeError(
            "No approved Nginx image is defined "
            "in the central security policy."
        )

    compose = yaml.safe_load(
        COMPOSE_FILE.read_text(
            encoding="utf-8"
        )
    )

    services = compose.get(
        "services",
        {}
    )

    nginx = services.get(
        "nginx"
    )

    if nginx is None:
        raise RuntimeError(
            "Docker Compose does not define "
            "an nginx service."
        )

    current_image = nginx.get(
        "image"
    )

    print(
        f"Current Nginx image:  {current_image}"
    )

    print(
        f"Approved Nginx image: {approved_image}"
    )

    if current_image == approved_image:
        print(
            "Nginx image already satisfies "
            "the central policy."
        )

        return

    nginx[
        "image"
    ] = approved_image

    COMPOSE_FILE.write_text(
        yaml.safe_dump(
            compose,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    print(
        "Nginx image updated to the "
        "approved versioned image."
    )


if __name__ == "__main__":
    main()
