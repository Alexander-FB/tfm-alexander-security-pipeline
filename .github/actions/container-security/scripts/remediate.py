from pathlib import Path
import os

import yaml


POLICY_FILE = Path(os.environ.get("CONTAINER_SECURITY_POLICY", "hardening-policy.yml"))
DOCKERFILE = Path("app/Dockerfile")
REQUIREMENTS_FILE = Path("app/requirements.txt")
COMPOSE_FILE = Path("docker-compose.yml")


# ---------------------------------------------------------------------
# Canonical YAML ordering
# ---------------------------------------------------------------------

TOP_LEVEL_ORDER = [
    "version",
    "name",
    "include",
    "services",
    "networks",
    "volumes",
    "secrets",
    "configs",
]


SERVICE_KEY_ORDER = [
    "image",
    "build",
    "container_name",
    "depends_on",
    "volumes",
    "volumes_from",
    "configs",
    "secrets",
    "environment",
    "env_file",
    "ports",
    "networks",
    "network_mode",
    "extra_hosts",
    "command",
    "entrypoint",
    "working_dir",
    "restart",
    "healthcheck",
    "logging",
    "labels",
    "user",
    "isolation",
    "cap_drop",
    "cpus",
    "mem_limit",
    "read_only",
    "security_opt",
]


PORT_KEY_ORDER = [
    "name",
    "target",
    "published",
    "host_ip",
    "protocol",
    "app_protocol",
    "mode",
]


def reorder_mapping(mapping, preferred_order):
    """
    Return a new mapping with known keys in canonical order.
    Unknown keys are preserved afterwards in their original order.
    """
    ordered = {}

    for key in preferred_order:
        if key in mapping:
            ordered[key] = mapping[key]

    for key, value in mapping.items():
        if key not in ordered:
            ordered[key] = value

    return ordered


# ---------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------

def load_policy():
    with POLICY_FILE.open() as file:
        return yaml.safe_load(file)


# ---------------------------------------------------------------------
# Dockerfile remediation
# ---------------------------------------------------------------------

def remediate_dockerfile(policy):
    config = policy["dockerfile"]

    lines = DOCKERFILE.read_text().splitlines()

    # Replace base image with the approved image.
    for index, line in enumerate(lines):
        if line.startswith("FROM "):
            lines[index] = f'FROM {config["base_image"]}'
            break
    else:
        raise ValueError("Dockerfile does not contain a FROM instruction")

    # Runtime settings required for the hardened read-only container.
    env_line = "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1"

    if not any(
        line.startswith("ENV PYTHONDONTWRITEBYTECODE")
        for line in lines
    ):
        from_index = next(
            index
            for index, line in enumerate(lines)
            if line.startswith("FROM ")
        )

        lines.insert(
            from_index + 1,
            env_line
        )

    # Remove directives managed by this engine before adding
    # the canonical hardened values.
    # This makes the transformation idempotent.
    lines = [
        line
        for line in lines
        if not line.startswith("USER ")
        and not line.startswith("HEALTHCHECK ")
    ]

    try:
        cmd_index = next(
            index
            for index, line in enumerate(lines)
            if line.startswith("CMD ")
        )
    except StopIteration as exc:
        raise ValueError(
            "Dockerfile does not contain a CMD instruction"
        ) from exc

    additions = []

    if config.get("add_healthcheck", True):
        additions.append(
            'HEALTHCHECK --interval=30s --timeout=5s --retries=3 '
            'CMD python -c "import urllib.request; '
            "urllib.request.urlopen("
            "'http://127.0.0.1:8000/health', timeout=3)\""
        )

    additions.append(
        f'USER {config["user"]}'
    )

    for offset, addition in enumerate(additions):
        lines.insert(
            cmd_index + offset,
            addition
        )

    DOCKERFILE.write_text(
        "\n".join(lines) + "\n"
    )


# ---------------------------------------------------------------------
# Dependency remediation
# ---------------------------------------------------------------------

def remediate_requirements(policy):
    approved_versions = policy.get(
        "dependencies",
        {}
    )

    output = []

    for line in REQUIREMENTS_FILE.read_text().splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue

        package_name = (
            stripped
            .split("==", 1)[0]
            .strip()
            .lower()
        )

        if package_name in approved_versions:
            output.append(
                f"{package_name}=="
                f"{approved_versions[package_name]}"
            )
        else:
            output.append(line)

    REQUIREMENTS_FILE.write_text(
        "\n".join(output) + "\n"
    )


# ---------------------------------------------------------------------
# Compose port normalization
# ---------------------------------------------------------------------

def compose_port_to_long_syntax(port, bind_address):
    """
    Convert a Docker Compose port mapping to long syntax.

    Supported short forms:
        8080:80
        8080:80/tcp
        127.0.0.1:8080:80

    Existing long-syntax mappings are preserved and normalized.

    The engine deliberately rejects unsupported/ambiguous formats
    instead of silently producing an incorrect Compose file.
    """

    if isinstance(port, dict):
        normalized = dict(port)

        if "published" in normalized:
            normalized["published"] = str(
                normalized["published"]
            )

        normalized["host_ip"] = bind_address

        return reorder_mapping(
            normalized,
            PORT_KEY_ORDER
        )

    value = str(port)

    protocol = "tcp"

    if "/" in value:
        value, protocol = value.rsplit("/", 1)

    parts = value.split(":")

    if len(parts) == 2:
        published, target = parts

    elif len(parts) == 3:
        _existing_host_ip, published, target = parts

    else:
        raise ValueError(
            f"Unsupported Compose port mapping: {port}"
        )

    try:
        target_port = int(target)
    except ValueError as exc:
        raise ValueError(
            f"Invalid container port: {target}"
        ) from exc

    mapping = {
        "target": target_port,
        "published": str(published),
        "host_ip": bind_address,
        "protocol": protocol,
    }

    return reorder_mapping(
        mapping,
        PORT_KEY_ORDER
    )


# ---------------------------------------------------------------------
# Docker Compose remediation
# ---------------------------------------------------------------------

def remediate_compose(policy):
    compose = yaml.safe_load(
        COMPOSE_FILE.read_text()
    )

    if not isinstance(compose, dict):
        raise ValueError(
            "docker-compose.yml does not contain a valid mapping"
        )

    services = compose.get("services")

    if not isinstance(services, dict):
        raise ValueError(
            "docker-compose.yml does not contain services"
        )

    config = policy["compose"]

    # -------------------------------------------------------------
    # Project metadata
    # -------------------------------------------------------------

    compose["name"] = config["project_name"]

    # -------------------------------------------------------------
    # API service
    # -------------------------------------------------------------

    if "api" not in services:
        raise ValueError(
            'Compose service "api" was not found'
        )

    api = services["api"]
    api_policy = config["api"]

    # CI/CD builds the image explicitly.
    # Compose only runs the resulting artifact.
    api.pop("build", None)

    api["image"] = api_policy["image"]

    if api_policy.get("drop_capabilities", False):
        api["cap_drop"] = [
            "ALL"
        ]
    else:
        api.pop("cap_drop", None)

    api["cpus"] = api_policy["cpus"]
    api["mem_limit"] = api_policy["memory_limit"]

    api["read_only"] = api_policy["read_only"]

    if api_policy.get("no_new_privileges", False):
        api["security_opt"] = [
            "no-new-privileges:true"
        ]
    else:
        api.pop("security_opt", None)

    # -------------------------------------------------------------
    # Nginx service
    # -------------------------------------------------------------

    if "nginx" not in services:
        raise ValueError(
            'Compose service "nginx" was not found'
        )

    nginx = services["nginx"]

    bind_address = config[
        "nginx"
    ]["bind_address"]

    # Convert Compose ports to structured long syntax.
    # No string generation or quote manipulation is required.
    nginx["ports"] = [
        compose_port_to_long_syntax(
            port,
            bind_address
        )
        for port in nginx.get("ports", [])
    ]

    # Make the Nginx configuration bind mount read-only.
    hardened_volumes = []

    for volume in nginx.get("volumes", []):
        # Preserve long-syntax volume definitions.
        if isinstance(volume, dict):
            hardened_volume = dict(volume)

            source = hardened_volume.get(
                "source",
                ""
            )

            if str(source).startswith("./nginx/"):
                hardened_volume["read_only"] = True

            hardened_volumes.append(
                hardened_volume
            )

            continue

        volume = str(volume)

        if (
            volume.startswith("./nginx/")
            and not volume.endswith(":ro")
        ):
            volume += ":ro"

        hardened_volumes.append(volume)

    nginx["volumes"] = hardened_volumes

    # -------------------------------------------------------------
    # Canonical ordering
    # -------------------------------------------------------------

    for service_name, service in services.items():
        services[service_name] = (
            reorder_mapping(
                service,
                SERVICE_KEY_ORDER
            )
        )

    compose["services"] = services

    compose = reorder_mapping(
        compose,
        TOP_LEVEL_ORDER
    )

    # -------------------------------------------------------------
    # Deterministic YAML serialization
    # -------------------------------------------------------------

    COMPOSE_FILE.write_text(
        yaml.safe_dump(
            compose,
            sort_keys=False,
            default_flow_style=False
        )
    )


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    policy = load_policy()

    remediate_dockerfile(policy)
    remediate_requirements(policy)
    remediate_compose(policy)

    print("Hardening policy applied successfully.")


if __name__ == "__main__":
    main()
