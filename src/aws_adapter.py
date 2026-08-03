from typing import Any


def get_resource_name_from_address(
    address: str,
) -> str:
    """
    Return the Terraform resource name from an address.

    Examples:
        aws_s3_bucket.customer_data
        becomes
        customer_data

        module.storage.aws_s3_bucket.customer_data
        becomes
        customer_data
    """
    parts = address.split(".")

    if not parts:
        return address

    return parts[-1]


def get_resource_type(
    resource: dict[str, Any],
) -> str:
    """
    Return the Terraform resource type.
    """
    resource_type = resource.get("type")

    if not isinstance(resource_type, str):
        return ""

    return resource_type


def get_resource_address(
    resource: dict[str, Any],
) -> str:
    """
    Return the Terraform resource address.
    """
    address = resource.get("address")

    if not isinstance(address, str):
        return ""

    return address


def get_resource_values(
    resource: dict[str, Any],
) -> dict[str, Any]:
    """
    Return the values object from a Terraform resource.
    """
    values = resource.get("values")

    if not isinstance(values, dict):
        return {}

    return values


def find_resources_by_type(
    resources: list[dict[str, Any]],
    resource_type: str,
) -> list[dict[str, Any]]:
    """
    Return every Terraform resource matching a specific type.
    """
    return [
        resource
        for resource in resources
        if get_resource_type(resource) == resource_type
    ]


def find_related_resource_by_name(
    resources: list[dict[str, Any]],
    resource_type: str,
    resource_name: str,
) -> dict[str, Any] | None:
    """
    Find a related Terraform resource using its Terraform name.

    Example:

        aws_s3_bucket.customer_data

    is related to:

        aws_s3_bucket_versioning.customer_data

    because both use the name:

        customer_data
    """
    for resource in resources:
        if get_resource_type(resource) != resource_type:
            continue

        address = get_resource_address(resource)

        if (
            get_resource_name_from_address(address)
            == resource_name
        ):
            return resource

    return None


def extract_s3_versioning_enabled(
    versioning_resource: dict[str, Any] | None,
) -> bool | None:
    """
    Extract whether S3 versioning is enabled.
    """
    if versioning_resource is None:
        return None

    values = get_resource_values(
        versioning_resource
    )

    configuration = values.get(
        "versioning_configuration"
    )

    if not isinstance(configuration, list):
        return None

    if not configuration:
        return None

    first_configuration = configuration[0]

    if not isinstance(first_configuration, dict):
        return None

    status = first_configuration.get("status")

    if not isinstance(status, str):
        return None

    return status.lower() == "enabled"


def extract_s3_encryption_enabled(
    encryption_resource: dict[str, Any] | None,
) -> bool | None:
    """
    Extract whether S3 server-side encryption is configured.

    Returns:
        True  - a valid encryption algorithm is configured.
        False - the encryption resource exists but no valid algorithm
                could be found.
        None  - no encryption resource was found.
    """
    if encryption_resource is None:
        return None

    values = get_resource_values(
        encryption_resource
    )

    rules = values.get("rule")

    if not isinstance(rules, list):
        return False

    if not rules:
        return False

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        defaults = rule.get(
            "apply_server_side_encryption_by_default"
        )

        if not isinstance(defaults, list):
            continue

        for default in defaults:
            if not isinstance(default, dict):
                continue

            algorithm = default.get(
                "sse_algorithm"
            )

            if isinstance(algorithm, str):
                if algorithm.upper() in {
                    "AES256",
                    "AWS:KMS",
                    "AWS:KMS:DSSE",
                }:
                    return True

    return False


def extract_s3_public_access(
    public_access_resource: dict[str, Any] | None,
) -> bool | None:
    """
    Determine whether public access is allowed.

    Returns:
        False - all public access protections are enabled.
        True  - one or more public access protections are disabled.
        None  - no public access block resource was found.
    """
    if public_access_resource is None:
        return None

    values = get_resource_values(
        public_access_resource
    )

    required_flags = [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ]

    flag_values: list[bool] = []

    for flag in required_flags:
        value = values.get(flag)

        if isinstance(value, bool):
            flag_values.append(value)
        else:
            return None

    all_public_access_blocked = all(
        flag_values
    )

    return not all_public_access_blocked


def extract_s3_logging_enabled(
    logging_resource: dict[str, Any] | None,
) -> bool | None:
    """
    Extract whether S3 access logging is configured.
    """
    if logging_resource is None:
        return None

    values = get_resource_values(
        logging_resource
    )

    target_bucket = values.get(
        "target_bucket"
    )

    target_prefix = values.get(
        "target_prefix"
    )

    if isinstance(target_bucket, str):
        if target_bucket.strip():
            return True

    if isinstance(target_prefix, str):
        if target_prefix.strip():
            return True

    return False


def add_control_if_known(
    controls: dict[str, Any],
    control_name: str,
    value: Any,
) -> None:
    """
    Add a control only when its value is known.

    None means the adapter could not determine the control.
    """
    if value is not None:
        controls[control_name] = value


def add_related_resource(
    related_resources: list[str],
    resource: dict[str, Any] | None,
) -> None:
    """
    Add the address of a related Terraform resource when present.
    """
    if resource is None:
        return

    address = get_resource_address(
        resource
    )

    if address:
        related_resources.append(
            address
        )


def normalise_s3_bucket(
    bucket_resource: dict[str, Any],
    all_resources: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Convert one AWS S3 bucket and its related configuration
    resources into the normalised infrastructure format.
    """
    bucket_address = get_resource_address(
        bucket_resource
    )

    bucket_name = get_resource_name_from_address(
        bucket_address
    )

    bucket_values = get_resource_values(
        bucket_resource
    )

    configured_bucket_name = bucket_values.get(
        "bucket"
    )

    versioning_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_s3_bucket_versioning",
        resource_name=bucket_name,
    )

    encryption_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type=(
            "aws_s3_bucket_"
            "server_side_encryption_configuration"
        ),
        resource_name=bucket_name,
    )

    public_access_resource = (
        find_related_resource_by_name(
            resources=all_resources,
            resource_type=(
                "aws_s3_bucket_public_access_block"
            ),
            resource_name=bucket_name,
        )
    )

    logging_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_s3_bucket_logging",
        resource_name=bucket_name,
    )

    controls: dict[str, Any] = {}

    add_control_if_known(
        controls,
        "versioning_enabled",
        extract_s3_versioning_enabled(
            versioning_resource
        ),
    )

    add_control_if_known(
        controls,
        "encryption_enabled",
        extract_s3_encryption_enabled(
            encryption_resource
        ),
    )

    add_control_if_known(
        controls,
        "public_access",
        extract_s3_public_access(
            public_access_resource
        ),
    )

    add_control_if_known(
        controls,
        "logging_enabled",
        extract_s3_logging_enabled(
            logging_resource
        ),
    )

    related_resources: list[str] = []

    add_related_resource(
        related_resources,
        versioning_resource,
    )

    add_related_resource(
        related_resources,
        encryption_resource,
    )

    add_related_resource(
        related_resources,
        public_access_resource,
    )

    add_related_resource(
        related_resources,
        logging_resource,
    )

    return {
        "id": bucket_address,
        "provider": "aws",
        "original_type": "aws_s3_bucket",
        "resource_type": "storage",
        "controls": controls,
        "metadata": {
            "terraform_address": bucket_address,
            "terraform_name": bucket_name,
            "bucket_name": configured_bucket_name,
            "related_resources": related_resources,
        },
    }


def normalise_aws_resources(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Convert supported AWS Terraform resources into the
    normalised infrastructure model.

    Current support:
        - aws_s3_bucket
        - aws_s3_bucket_versioning
        - aws_s3_bucket_server_side_encryption_configuration
        - aws_s3_bucket_public_access_block
        - aws_s3_bucket_logging
    """
    normalised_resources: list[dict[str, Any]] = []

    s3_buckets = find_resources_by_type(
        resources,
        "aws_s3_bucket",
    )

    for bucket_resource in s3_buckets:
        normalised_resources.append(
            normalise_s3_bucket(
                bucket_resource=bucket_resource,
                all_resources=resources,
            )
        )

    return normalised_resources