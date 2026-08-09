"""
This module turns AWS-specific Terraform resources into the generic
controls the policies use, e.g. aws_s3_bucket_versioning becomes
versioning_enabled.

The policies should never need to know AWS resource names. That way
the same policies could be reused for another cloud later without
rewriting them, just by writing a different adapter.

Covers S3, security groups, CloudTrail, auto-scaling groups, CloudWatch
alarms, KMS keys, RDS instances and IAM roles, plus a plan-wide scan
for plaintext secrets and GDPR tags. See normalise_aws_resources at
the bottom for the full list.
"""

import json
from typing import Any


def get_resource_name_from_address(
    address: str,
) -> str:
    """
    Return the Terraform resource name from an address.

    Examples:
        aws_s3_bucket.customer_data
        becomes:
        customer_data

        module.storage.aws_s3_bucket.customer_data
        becomes:
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

    Example:
        aws_s3_bucket
    """
    resource_type = resource.get("type")

    if not isinstance(resource_type, str):
        return ""

    return resource_type


def get_resource_address(
    resource: dict[str, Any],
) -> str:
    """
    Return the full Terraform resource address.

    Example:
        aws_s3_bucket.customer_data
    """
    address = resource.get("address")

    if not isinstance(address, str):
        return ""

    return address


def get_resource_values(
    resource: dict[str, Any],
) -> dict[str, Any]:
    """
    Return the configuration values stored in a Terraform resource.
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
    Return every Terraform resource matching a specific resource type.
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
    Find a related Terraform resource by matching its Terraform name.

    Example:

        aws_s3_bucket.customer_data

    is treated as related to:

        aws_s3_bucket_versioning.customer_data

    because both resources use the Terraform name:

        customer_data

    Limitation:
        This is suitable for the current prototype, where related resources
        share the same Terraform name. A future version could also inspect
        explicit Terraform references and dependencies.
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
    bucket_values: dict[str, Any],
) -> bool | None:
    """
    Work out whether S3 versioning is enabled.

    Checks the separate aws_s3_bucket_versioning resource first (the
    newer way Terraform does it, provider v4+). If that's not there,
    falls back to the older inline `versioning {}` block inside
    aws_s3_bucket itself, since older Terraform still uses that style.
    Without this fallback a bucket that really does have versioning on
    looks the same as one with no versioning at all - this happened
    when testing against TerraGoat.

    Returns:
        True:
            Versioning is enabled, in either resource shape.

        False:
            A versioning resource or inline block exists, but the
            status is not Enabled.

        None:
            No versioning resource and no inline block was found, or
            the value could not be determined.
    """
    if versioning_resource is not None:
        values = get_resource_values(
            versioning_resource
        )

        configuration = values.get(
            "versioning_configuration"
        )

        return extract_versioning_status(configuration)

    inline_versioning = bucket_values.get("versioning")

    return extract_versioning_status(inline_versioning)


def extract_versioning_status(
    configuration: Any,
) -> bool | None:
    """
    Shared parsing for the single-element "status"/"enabled" list
    shape that both versioning representations use.
    """
    if not isinstance(configuration, list) or not configuration:
        return None

    first_configuration = configuration[0]

    if not isinstance(first_configuration, dict):
        return None

    if "status" in first_configuration:
        status = first_configuration.get("status")

        if not isinstance(status, str):
            return None

        return status.lower() == "enabled"

    enabled = first_configuration.get("enabled")

    return enabled if isinstance(enabled, bool) else None


def extract_encryption_from_rule_list(
    rules: Any,
) -> bool | None:
    """
    Shared parsing for the `rule` structure that appears identically
    in both aws_s3_bucket_server_side_encryption_configuration and the
    older inline server_side_encryption_configuration {} block.

    Supported algorithms:
        AES256
        aws:kms
        aws:kms:dsse
    """
    if not isinstance(rules, list) or not rules:
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

            if not isinstance(algorithm, str):
                continue

            if algorithm.upper() in {
                "AES256",
                "AWS:KMS",
                "AWS:KMS:DSSE",
            }:
                return True

    return False


def extract_s3_encryption_enabled(
    encryption_resource: dict[str, Any] | None,
    bucket_values: dict[str, Any],
) -> bool | None:
    """
    Extract whether S3 server-side encryption is configured.

    Checks the decoupled
    aws_s3_bucket_server_side_encryption_configuration resource first,
    falling back to the older inline
    server_side_encryption_configuration {} block for the same reason
    documented on extract_s3_versioning_enabled.

    Returns:
        True:
            A supported encryption algorithm is configured, in either
            resource shape.

        False:
            An encryption resource or inline block exists, but no
            supported algorithm could be found.

        None:
            Neither an encryption resource nor an inline block was
            found.
    """
    if encryption_resource is not None:
        values = get_resource_values(
            encryption_resource
        )

        return extract_encryption_from_rule_list(
            values.get("rule")
        )

    inline_configuration = bucket_values.get(
        "server_side_encryption_configuration"
    )

    if not isinstance(inline_configuration, list) or not inline_configuration:
        return None

    first_block = inline_configuration[0]

    if not isinstance(first_block, dict):
        return None

    return extract_encryption_from_rule_list(
        first_block.get("rule")
    )


def extract_s3_public_access(
    public_access_resource: dict[str, Any] | None,
) -> bool | None:
    """
    Determine whether the S3 bucket permits public access.

    The adapter checks these four AWS public-access settings:

        block_public_acls
        block_public_policy
        ignore_public_acls
        restrict_public_buckets

    Returns:
        False:
            All four protections are enabled, meaning public access is
            blocked.

        True:
            One or more protections are disabled, meaning public access
            may be possible.

        None:
            No public-access block resource was found, or one of the
            settings could not be determined.
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

        if not isinstance(value, bool):
            return None

        flag_values.append(value)

    all_public_access_blocked = all(
        flag_values
    )

    return not all_public_access_blocked


def extract_logging_target_present(
    values: dict[str, Any],
) -> bool:
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


def extract_s3_logging_enabled(
    logging_resource: dict[str, Any] | None,
    bucket_values: dict[str, Any],
) -> bool | None:
    """
    Extract whether S3 access logging is configured.

    Checks the decoupled aws_s3_bucket_logging resource first, falling
    back to the older inline `logging {}` block for the same reason
    documented on extract_s3_versioning_enabled.

    Returns:
        True:
            A target bucket or target prefix is configured, in either
            resource shape.

        False:
            A logging resource or inline block exists, but no usable
            destination was identified.

        None:
            Neither a logging resource nor an inline block was found.
    """
    if logging_resource is not None:
        return extract_logging_target_present(
            get_resource_values(logging_resource)
        )

    inline_logging = bucket_values.get("logging")

    if not isinstance(inline_logging, list) or not inline_logging:
        return None

    first_block = inline_logging[0]

    if not isinstance(first_block, dict):
        return None

    return extract_logging_target_present(first_block)


def extract_s3_backup_enabled(
    configured_bucket_name: str | None,
    bucket_name: str,
    all_resources: list[dict[str, Any]],
) -> bool | None:
    """
    Check whether the S3 bucket is covered by an AWS Backup selection.

    AWS Backup resource IDs are generated by AWS, so they don't exist
    yet in a Terraform plan and can't be used to link things up. So
    this links the backup selection to the bucket the same way the
    rest of this file does it: match by Terraform resource name, then
    check the selection actually lists this bucket's ARN.

    Returns:
        True:
            A backup selection with this bucket's Terraform name exists
            and its resource list covers this bucket.

        False:
            No such selection exists, or it exists but doesn't cover
            this bucket.

        None:
            The bucket's configured name couldn't be worked out, so we
            can't build its ARN to check.
    """
    if not configured_bucket_name:
        return None

    selection_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_backup_selection",
        resource_name=bucket_name,
    )

    if selection_resource is None:
        return False

    values = get_resource_values(selection_resource)
    covered_resources = values.get("resources")

    if not isinstance(covered_resources, list):
        return False

    expected_arn = f"arn:aws:s3:::{configured_bucket_name}"

    return expected_arn in covered_resources or "*" in covered_resources


def extract_s3_backup_encryption_enabled(
    backup_enabled: bool | None,
    bucket_name: str,
    all_resources: list[dict[str, Any]],
) -> bool | None:
    """
    Determine whether the backup vault protecting this bucket has a
    customer-managed KMS key attached.

    Encryption of a backup is only meaningful once a backup exists, so
    this mirrors backup_enabled's None/False rather than re-deriving
    its own answer when there is nothing to check.
    """
    if backup_enabled is None:
        return None

    if backup_enabled is False:
        return False

    vault_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_backup_vault",
        resource_name=bucket_name,
    )

    if vault_resource is None:
        return False

    values = get_resource_values(vault_resource)
    kms_key_arn = values.get("kms_key_arn")

    return isinstance(kms_key_arn, str) and bool(kms_key_arn.strip())


def add_control_if_known(
    controls: dict[str, Any],
    control_name: str,
    value: Any,
) -> None:
    """
    Add a control to the normalised resource only when its value is known.

    A value of None means that the adapter could not determine the control
    from the Terraform plan.

    Unknown controls are left absent so that the policy engine can report
    them as missing rather than incorrectly assuming that they pass.
    """
    if value is not None:
        controls[control_name] = value


def add_related_resource(
    related_resources: list[str],
    resource: dict[str, Any] | None,
) -> None:
    """
    Add the Terraform address of a related configuration resource.

    This provides traceability by recording which original Terraform
    resources were merged into the normalised resource.
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
    Convert one AWS S3 bucket and its related Terraform configuration
    resources into one generic storage resource.

    Several AWS Terraform resources can describe different parts of the
    same logical bucket. This function finds and merges those related
    resources before extracting generic security controls.
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

    public_access_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type=(
            "aws_s3_bucket_public_access_block"
        ),
        resource_name=bucket_name,
    )

    logging_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_s3_bucket_logging",
        resource_name=bucket_name,
    )

    controls: dict[str, Any] = {}

    versioning_enabled = extract_s3_versioning_enabled(
        versioning_resource,
        bucket_values,
    )

    encryption_enabled = extract_s3_encryption_enabled(
        encryption_resource,
        bucket_values,
    )

    public_access = extract_s3_public_access(
        public_access_resource
    )

    logging_enabled = extract_s3_logging_enabled(
        logging_resource,
        bucket_values,
    )

    backup_enabled = extract_s3_backup_enabled(
        configured_bucket_name=(
            configured_bucket_name
            if isinstance(configured_bucket_name, str)
            else None
        ),
        bucket_name=bucket_name,
        all_resources=all_resources,
    )

    backup_encryption_enabled = extract_s3_backup_encryption_enabled(
        backup_enabled=backup_enabled,
        bucket_name=bucket_name,
        all_resources=all_resources,
    )

    add_control_if_known(
        controls,
        "versioning_enabled",
        versioning_enabled,
    )

    add_control_if_known(
        controls,
        "encryption_enabled",
        encryption_enabled,
    )

    add_control_if_known(
        controls,
        "public_access",
        public_access,
    )

    add_control_if_known(
        controls,
        "logging_enabled",
        logging_enabled,
    )

    add_control_if_known(
        controls,
        "backup_enabled",
        backup_enabled,
    )

    add_control_if_known(
        controls,
        "backup_encryption_enabled",
        backup_encryption_enabled,
    )

    # Derived control:
    # If public access is blocked, the bucket is considered private by
    # default for the purposes of the current prototype.
    if public_access is not None:
        controls["private_by_default"] = (
            not public_access
        )

    # Prototype interpretation:
    # A complete S3 public-access block is treated as evidence that basic
    # access restrictions are enabled.
    #
    # This does not prove full IAM least privilege or guarantee that every
    # authorised identity has the correct permissions. More detailed IAM
    # and bucket-policy analysis would be required for that.
    if public_access is not None:
        controls["access_control_enabled"] = (
            not public_access
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

    add_related_resource(
        related_resources,
        find_related_resource_by_name(
            resources=all_resources,
            resource_type="aws_backup_selection",
            resource_name=bucket_name,
        ),
    )

    add_related_resource(
        related_resources,
        find_related_resource_by_name(
            resources=all_resources,
            resource_type="aws_backup_vault",
            resource_name=bucket_name,
        ),
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
            "normalisation_notes": [
                (
                    "private_by_default is derived from the "
                    "public_access result."
                ),
                (
                    "access_control_enabled is currently inferred from "
                    "the complete S3 public-access block. This does not "
                    "prove full IAM least privilege."
                ),
            ],
        },
    }


## ---------------------------------------------------------------------
## Network: security groups (inbound exposure) and load balancer
## listeners (transport encryption)
## ---------------------------------------------------------------------

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22, 3389}


def rule_allows_public_access(
    rule: dict[str, Any],
) -> bool:
    """
    Return True when a security group rule permits traffic from
    anywhere on the Internet (IPv4 or IPv6).
    """
    all_cidrs: list[Any] = []

    cidr_blocks = rule.get("cidr_blocks")
    if isinstance(cidr_blocks, list):
        all_cidrs.extend(cidr_blocks)

    ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks")
    if isinstance(ipv6_cidr_blocks, list):
        all_cidrs.extend(ipv6_cidr_blocks)

    return any(cidr in PUBLIC_CIDRS for cidr in all_cidrs)


def rule_covers_admin_port(
    rule: dict[str, Any],
) -> bool:
    """
    Return True when a security group rule's port range includes a
    well-known administrative port (SSH, RDP).
    """
    from_port = rule.get("from_port")
    to_port = rule.get("to_port")

    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return False

    return any(from_port <= port <= to_port for port in ADMIN_PORTS)


def extract_lb_listener_tls_enabled(
    listener_resource: dict[str, Any] | None,
) -> bool | None:
    if listener_resource is None:
        return None

    values = get_resource_values(listener_resource)
    protocol = values.get("protocol")

    return (
        isinstance(protocol, str) and protocol.upper() in {"HTTPS", "TLS"}
    )


def normalise_network_perimeter(
    sg_resource: dict[str, Any],
    all_resources: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Convert one AWS security group into a generic network resource,
    merging in the load balancer listener that shares its Terraform
    name (same idea as normalise_s3_bucket merging S3's sub-resources).

    A security group and its listener are two different resources
    describing one thing: the network entry point. If they were kept
    as two separate "network" resources, each one would look like it's
    missing the controls the other one owns (a security group has no
    TLS setting, a listener has no ingress rules), and both would get
    flagged as non-compliant for something that was never theirs to
    have. Merging them avoids that.
    """
    address = get_resource_address(sg_resource)
    sg_name = get_resource_name_from_address(address)
    values = get_resource_values(sg_resource)

    ingress_rules = values.get("ingress")
    ingress_rules = (
        [rule for rule in ingress_rules if isinstance(rule, dict)]
        if isinstance(ingress_rules, list)
        else []
    )

    unrestricted_ingress = any(
        rule_allows_public_access(rule) for rule in ingress_rules
    )

    admin_interface_public = any(
        rule_allows_public_access(rule) and rule_covers_admin_port(rule)
        for rule in ingress_rules
    )

    listener_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_lb_listener",
        resource_name=sg_name,
    )

    tls_enabled = extract_lb_listener_tls_enabled(listener_resource)

    controls: dict[str, Any] = {
        "unrestricted_ingress": unrestricted_ingress,
        "admin_interface_public": admin_interface_public,
    }

    add_control_if_known(controls, "tls_enabled", tls_enabled)

    related_resources: list[str] = []
    add_related_resource(related_resources, listener_resource)

    return {
        "id": address,
        "provider": "aws",
        "original_type": "aws_security_group",
        "resource_type": "network",
        "controls": controls,
        "metadata": {
            "terraform_address": address,
            "terraform_name": sg_name,
            "related_resources": related_resources,
            "normalisation_notes": [
                (
                    "tls_enabled is taken from the load balancer "
                    "listener sharing this security group's Terraform "
                    "name, not from the security group itself, which "
                    "has no transport-encryption setting of its own. "
                    "A security group with no associated listener in "
                    "the plan leaves tls_enabled unset rather than "
                    "guessed."
                ),
            ],
        },
    }


def normalise_network_perimeters(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        normalise_network_perimeter(sg_resource, resources)
        for sg_resource in find_resources_by_type(
            resources, "aws_security_group"
        )
    ]


## ---------------------------------------------------------------------
## Logging: CloudTrail, linked to its CloudWatch log group by Terraform
## name, the same convention the S3 adapter uses.
## ---------------------------------------------------------------------


def extract_log_retention_days(
    trail_name: str,
    all_resources: list[dict[str, Any]],
) -> int | None:
    log_group_resource = find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_cloudwatch_log_group",
        resource_name=trail_name,
    )

    if log_group_resource is None:
        return None

    values = get_resource_values(log_group_resource)
    retention_in_days = values.get("retention_in_days")

    return (
        retention_in_days
        if isinstance(retention_in_days, int)
        else None
    )


def normalise_cloudtrail(
    trail_resource: dict[str, Any],
    all_resources: list[dict[str, Any]],
) -> dict[str, Any]:
    address = get_resource_address(trail_resource)
    trail_name = get_resource_name_from_address(address)
    values = get_resource_values(trail_resource)

    logging_enabled = values.get("enable_logging")
    log_immutability_enabled = values.get("enable_log_file_validation")
    log_retention_days = extract_log_retention_days(
        trail_name, all_resources
    )

    controls: dict[str, Any] = {}

    add_control_if_known(
        controls,
        "logging_enabled",
        logging_enabled if isinstance(logging_enabled, bool) else None,
    )

    add_control_if_known(
        controls,
        "log_immutability_enabled",
        (
            log_immutability_enabled
            if isinstance(log_immutability_enabled, bool)
            else None
        ),
    )

    add_control_if_known(
        controls,
        "log_retention_days",
        log_retention_days,
    )

    return {
        "id": address,
        "provider": "aws",
        "original_type": "aws_cloudtrail",
        "resource_type": "logging",
        "controls": controls,
        "metadata": {
            "terraform_address": address,
            "terraform_name": trail_name,
        },
    }


def normalise_cloudtrails(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        normalise_cloudtrail(trail_resource, resources)
        for trail_resource in find_resources_by_type(
            resources, "aws_cloudtrail"
        )
    ]


## ---------------------------------------------------------------------
## Compute: auto-scaling groups
## ---------------------------------------------------------------------


def normalise_autoscaling_group(
    asg_resource: dict[str, Any],
) -> dict[str, Any]:
    address = get_resource_address(asg_resource)
    values = get_resource_values(asg_resource)

    desired_capacity = values.get("desired_capacity")
    health_check_type = values.get("health_check_type")
    health_check_grace_period = values.get("health_check_grace_period")
    availability_zones = values.get("availability_zones")

    replica_count = (
        desired_capacity if isinstance(desired_capacity, int) else None
    )

    health_check_enabled = (
        isinstance(health_check_type, str)
        and bool(health_check_type.strip())
    )

    multi_az_enabled = (
        isinstance(availability_zones, list)
        and len(availability_zones) > 1
    )

    # A stricter signal than health_check_enabled on purpose: recovery
    # requires load-balancer-based health checks *and* a configured
    # grace period, not merely any health check type being set.
    recovery_enabled = (
        health_check_type == "ELB"
        and isinstance(health_check_grace_period, int)
        and health_check_grace_period > 0
    )

    controls: dict[str, Any] = {}
    add_control_if_known(controls, "replica_count", replica_count)
    controls["health_check_enabled"] = health_check_enabled
    controls["multi_az_enabled"] = multi_az_enabled
    controls["recovery_enabled"] = recovery_enabled

    return {
        "id": address,
        "provider": "aws",
        "original_type": "aws_autoscaling_group",
        "resource_type": "compute",
        "controls": controls,
        "metadata": {
            "terraform_address": address,
        },
    }


def normalise_autoscaling_groups(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        normalise_autoscaling_group(asg_resource)
        for asg_resource in find_resources_by_type(
            resources, "aws_autoscaling_group"
        )
    ]


## ---------------------------------------------------------------------
## Monitoring: CloudWatch alarms
## ---------------------------------------------------------------------


def normalise_cloudwatch_alarm(
    alarm_resource: dict[str, Any],
) -> dict[str, Any]:
    address = get_resource_address(alarm_resource)

    return {
        "id": address,
        "provider": "aws",
        "original_type": "aws_cloudwatch_metric_alarm",
        "resource_type": "monitoring",
        "controls": {
            "monitoring_enabled": True,
        },
        "metadata": {
            "terraform_address": address,
        },
    }


def normalise_cloudwatch_alarms(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        normalise_cloudwatch_alarm(alarm_resource)
        for alarm_resource in find_resources_by_type(
            resources, "aws_cloudwatch_metric_alarm"
        )
    ]


## ---------------------------------------------------------------------
## Encryption key: customer-managed KMS keys
## ---------------------------------------------------------------------


def normalise_kms_key(
    key_resource: dict[str, Any],
) -> dict[str, Any]:
    address = get_resource_address(key_resource)
    values = get_resource_values(key_resource)

    key_rotation_enabled = values.get("enable_key_rotation")

    controls: dict[str, Any] = {}
    add_control_if_known(
        controls,
        "key_rotation_enabled",
        (
            key_rotation_enabled
            if isinstance(key_rotation_enabled, bool)
            else None
        ),
    )

    # Heuristic, not proof: a dedicated KMS key resource is treated as
    # evidence that key material is managed separately from the data
    # it protects. This is why the policy this feeds is only "partial"
    # automation rather than "full".
    controls["key_stored_separately"] = True

    return {
        "id": address,
        "provider": "aws",
        "original_type": "aws_kms_key",
        "resource_type": "encryption_key",
        "controls": controls,
        "metadata": {
            "terraform_address": address,
        },
    }


def normalise_kms_keys(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        normalise_kms_key(key_resource)
        for key_resource in find_resources_by_type(
            resources, "aws_kms_key"
        )
    ]


## ---------------------------------------------------------------------
## Identity: IAM roles, linked to their inline policy by Terraform name
## ---------------------------------------------------------------------


def contains_mfa_condition(
    assume_role_policy_json: str,
) -> bool:
    return "MultiFactorAuthPresent" in assume_role_policy_json


def role_trust_policy_is_service_only(
    assume_role_policy_json: str,
) -> bool | None:
    """
    Check whether every principal allowed to assume this role is an
    AWS service (e.g. ec2.amazonaws.com), not a human user or a
    federated identity.

    MFA only makes sense for a principal that can actually log in with
    MFA. An AWS service calling sts:AssumeRole can't do that, so
    checking privileged_mfa_enabled on a service-only role doesn't
    make sense - it flagged 3 EC2/Lambda/EKS roles as non-compliant
    when testing against TerraGoat, and Checkov doesn't flag any of
    them for MFA either, which is what made me notice this.

    Returns:
        True:
            Every statement's Principal is AWS-service-only.

        False:
            At least one statement allows an AWS account, IAM user, or
            federated identity to assume the role -- MFA is a
            meaningful question here.

        None:
            The trust policy could not be parsed, so this cannot be
            determined either way.
    """
    try:
        document = json.loads(assume_role_policy_json)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(document, dict):
        return None

    statements = document.get("Statement")

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list) or not statements:
        return None

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        principal = statement.get("Principal")

        if not isinstance(principal, dict):
            # A bare "*" principal, or a shape this adapter doesn't
            # recognise: treat MFA as a meaningful question rather
            # than silently skipping the check.
            return False

        if "AWS" in principal or "Federated" in principal:
            return False

    return True


def policy_document_is_least_privilege(
    policy_json: str,
) -> bool | None:
    """
    Flag obvious wildcard Action/Resource statements in an IAM policy
    document.

    This can only catch the clearest cases. It cannot determine the
    exact permissions each identity genuinely needs, which is why the
    policy this feeds is "partial" automation, not "full".
    """
    try:
        document = json.loads(policy_json)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(document, dict):
        return None

    statements = document.get("Statement")

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return None

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow":
            continue

        for field in ("Action", "Resource"):
            value = statement.get(field)

            if value == "*":
                return False

            if isinstance(value, list) and "*" in value:
                return False

    return True


def find_role_policy_by_reference(
    role_address: str,
    all_resources: list[dict[str, Any]],
    references: dict[str, dict[str, list[str]]],
) -> dict[str, Any] | None:
    """
    Find the aws_iam_role_policy resource whose `role` argument
    references this role, using the plan's configuration data instead
    of matching Terraform resource names.

    Name-matching (what the rest of this file uses) assumes a role and
    its inline policy share a Terraform name. That's not always true -
    in TerraGoat, aws_iam_role.ec2role's policy is actually named
    aws_iam_role_policy.ec2policy. The plan's `configuration` block
    still records that its `role` argument points at
    aws_iam_role.ec2role, even though the role's real ID is only known
    after apply, so we can use that reference instead of the name.
    """
    for resource in find_resources_by_type(
        all_resources, "aws_iam_role_policy"
    ):
        address = get_resource_address(resource)
        role_references = references.get(address, {}).get("role", [])

        if any(
            reference == role_address
            or reference.startswith(f"{role_address}.")
            for reference in role_references
        ):
            return resource

    return None


def find_iam_role_inline_policy(
    role_address: str,
    role_name: str,
    all_resources: list[dict[str, Any]],
    references: dict[str, dict[str, list[str]]],
) -> dict[str, Any] | None:
    """
    Resolve a role's inline aws_iam_role_policy, preferring the plan's
    actual reference graph over name-matching, and falling back to
    name-matching only when no configuration data is available (for
    example, a plan JSON produced without the `configuration` block).
    """
    if references:
        by_reference = find_role_policy_by_reference(
            role_address=role_address,
            all_resources=all_resources,
            references=references,
        )

        if by_reference is not None:
            return by_reference

    return find_related_resource_by_name(
        resources=all_resources,
        resource_type="aws_iam_role_policy",
        resource_name=role_name,
    )


def normalise_iam_role(
    role_resource: dict[str, Any],
    all_resources: list[dict[str, Any]],
    references: dict[str, dict[str, list[str]]],
) -> dict[str, Any]:
    address = get_resource_address(role_resource)
    role_name = get_resource_name_from_address(address)
    values = get_resource_values(role_resource)

    assume_role_policy = values.get("assume_role_policy")

    privileged_mfa_enabled = None
    mfa_not_applicable = False

    if isinstance(assume_role_policy, str):
        if role_trust_policy_is_service_only(assume_role_policy) is True:
            mfa_not_applicable = True
            privileged_mfa_enabled = True
        else:
            privileged_mfa_enabled = contains_mfa_condition(
                assume_role_policy
            )

    inline_policy_resource = find_iam_role_inline_policy(
        role_address=address,
        role_name=role_name,
        all_resources=all_resources,
        references=references,
    )

    least_privilege_enforced = None
    if inline_policy_resource is not None:
        policy_values = get_resource_values(inline_policy_resource)
        policy_document = policy_values.get("policy")

        if isinstance(policy_document, str):
            least_privilege_enforced = (
                policy_document_is_least_privilege(policy_document)
            )

    controls: dict[str, Any] = {}
    add_control_if_known(
        controls, "privileged_mfa_enabled", privileged_mfa_enabled
    )
    add_control_if_known(
        controls, "least_privilege_enforced", least_privilege_enforced
    )

    normalisation_notes = []

    if mfa_not_applicable:
        normalisation_notes.append(
            "privileged_mfa_enabled is marked compliant because this "
            "role's trust policy only allows an AWS service principal "
            "to assume it -- MFA-on-assume-role has no meaning for a "
            "service principal, not because MFA was actually "
            "configured or verified."
        )
    else:
        normalisation_notes.append(
            "privileged_mfa_enabled checks whether the role's trust "
            "policy references the aws:MultiFactorAuthPresent "
            "condition key. It cannot prove that every administrator "
            "has actually enrolled in MFA."
        )

    normalisation_notes.append(
        "least_privilege_enforced flags obvious wildcard Action or "
        "Resource statements in the role's inline policy. It cannot "
        "determine the exact permissions each identity genuinely "
        "needs."
    )

    return {
        "id": address,
        "provider": "aws",
        "original_type": "aws_iam_role",
        "resource_type": "identity",
        "controls": controls,
        "metadata": {
            "terraform_address": address,
            "terraform_name": role_name,
            "normalisation_notes": normalisation_notes,
        },
    }


def normalise_iam_roles(
    resources: list[dict[str, Any]],
    references: dict[str, dict[str, list[str]]],
) -> list[dict[str, Any]]:
    return [
        normalise_iam_role(role_resource, resources, references)
        for role_resource in find_resources_by_type(
            resources, "aws_iam_role"
        )
    ]


## ---------------------------------------------------------------------
## Secrets: a plan-wide sweep for plaintext-looking sensitive values
## ---------------------------------------------------------------------

SENSITIVE_KEY_MARKERS = (
    "password",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "access_key",
)

SAFE_KEY_SUFFIXES = ("_arn", "_id")


def looks_like_sensitive_key(
    key: str,
) -> bool:
    lowered = key.lower()

    if lowered.endswith(SAFE_KEY_SUFFIXES):
        return False

    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def find_plaintext_secret(
    value: Any,
    key: str = "",
) -> bool:
    """
    Recursively search a resource's planned values for a literal,
    non-empty string stored under a sensitive-sounding key name.

    Every value considered here already came from planned_values, so
    an unresolved reference (a value only known after apply) would
    already be absent, not a string. Any literal string surviving to
    this point is therefore always a real, plan-time-known value.
    """
    if isinstance(value, dict):
        return any(
            find_plaintext_secret(nested_value, nested_key)
            for nested_key, nested_value in value.items()
        )

    if isinstance(value, list):
        return any(find_plaintext_secret(item, key) for item in value)

    if isinstance(value, str):
        return looks_like_sensitive_key(key) and bool(value.strip())

    return False


def normalise_secrets_exposure(
    resources: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Always returns one "secrets" resource, whether or not anything
    suspicious was found, so the policy checking plaintext_secrets is
    genuinely exercised in both the compliant and non-compliant case
    instead of only ever matching when something is already wrong.
    """
    plaintext_secrets = any(
        find_plaintext_secret(get_resource_values(resource))
        for resource in resources
    )

    return {
        "id": "aws.plaintext_secret_scan",
        "provider": "aws",
        "original_type": "terraform_plan",
        "resource_type": "secrets",
        "controls": {
            "plaintext_secrets": plaintext_secrets,
        },
        "metadata": {
            "normalisation_notes": [
                (
                    "Heuristic scan of literal string values against "
                    "sensitive-sounding attribute names (password, "
                    "secret, api_key, private_key, access_key). It can "
                    "miss secrets stored under unrecognised names and "
                    "can flag values that are not actually secret."
                ),
            ],
        },
    }


## ---------------------------------------------------------------------
## Governance: GDPR risk/assessment metadata read from a tagging
## convention, since it has no infrastructure representation of its
## own.
## ---------------------------------------------------------------------

GOVERNANCE_TAG_CONTROLS = {
    "gdpr_high_risk_processing": "high_risk_processing",
    "gdpr_dpia_completed": "dpia_completed",
}


def extract_governance_controls_from_tags(
    tags: dict[str, Any],
) -> dict[str, Any]:
    controls: dict[str, Any] = {}

    for tag_key, control_name in GOVERNANCE_TAG_CONTROLS.items():
        tag_value = tags.get(tag_key)

        if isinstance(tag_value, str):
            controls[control_name] = tag_value.strip().lower() == "true"
        elif isinstance(tag_value, bool):
            controls[control_name] = tag_value

    return controls


def normalise_governance_tags(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    governance_resources: list[dict[str, Any]] = []

    for resource in resources:
        values = get_resource_values(resource)
        tags = values.get("tags")

        if not isinstance(tags, dict):
            continue

        controls = extract_governance_controls_from_tags(tags)

        if not controls:
            continue

        address = get_resource_address(resource)

        governance_resources.append({
            "id": f"{address}#governance",
            "provider": "aws",
            "original_type": get_resource_type(resource),
            "resource_type": "governance",
            "controls": controls,
            "metadata": {
                "terraform_address": address,
                "normalisation_notes": [
                    (
                        "Derived from the gdpr_high_risk_processing / "
                        "gdpr_dpia_completed tags on this resource, not "
                        "from a real governance record. Tags can be set "
                        "incorrectly or omitted; this cannot substitute "
                        "for an actual DPIA document."
                    ),
                ],
            },
        })

    return governance_resources


## ---------------------------------------------------------------------
## Processing system: a system-wide composite synthesised from signals
## already normalised for individual resources.
## ---------------------------------------------------------------------


def synthesise_processing_system(
    normalised_resources: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """
    GDPR-32-SECURITYSET-001 checks "the processing system" as a whole,
    not any single bucket or trail, so it needs one aggregate resource
    rather than a Terraform resource type of its own.

    Returns None when there is no storage resource to aggregate over,
    since a processing system with no data store to protect is not a
    meaningful thing to assess here.
    """
    storage_resources = [
        resource
        for resource in normalised_resources
        if resource.get("resource_type") == "storage"
    ]

    if not storage_resources:
        return None

    logging_resources = [
        resource
        for resource in normalised_resources
        if resource.get("resource_type") == "logging"
    ]

    def all_storage_resources_confirm(control_name: str) -> bool:
        return all(
            resource.get("controls", {}).get(control_name) is True
            for resource in storage_resources
        )

    def any_logging_resource_confirms(control_name: str) -> bool:
        return any(
            resource.get("controls", {}).get(control_name) is True
            for resource in logging_resources
        )

    controls = {
        "encryption_enabled": all_storage_resources_confirm(
            "encryption_enabled"
        ),
        "access_control_enabled": all_storage_resources_confirm(
            "access_control_enabled"
        ),
        "backup_enabled": all_storage_resources_confirm(
            "backup_enabled"
        ),
        "logging_enabled": any_logging_resource_confirms(
            "logging_enabled"
        ),
    }

    return {
        "id": "aws.processing_system",
        "provider": "aws",
        "original_type": "terraform_plan",
        "resource_type": "processing_system",
        "controls": controls,
        "metadata": {
            "normalisation_notes": [
                (
                    "Synthesised, not read from a single Terraform "
                    "resource: aggregates signals already normalised "
                    "for individual resources. encryption_enabled, "
                    "access_control_enabled and backup_enabled require "
                    "every storage resource to confirm the control; "
                    "logging_enabled requires at least one logging "
                    "resource to confirm it."
                ),
            ],
        },
    }


## ---------------------------------------------------------------------
## Database: RDS instances.
## ---------------------------------------------------------------------


def normalise_rds_instance(
    db_resource: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert one AWS RDS instance into a generic database resource.

    Each control just reads one attribute straight off the resource.
    If Terraform never set that attribute (e.g. multi_az left out
    entirely), it won't be known at plan time, so we leave it out
    rather than guess - same rule as everywhere else in this file.

    Note: this doesn't cover aws_rds_cluster (Aurora). That's a
    different resource shape and would need its own function.
    """
    address = get_resource_address(db_resource)
    values = get_resource_values(db_resource)

    publicly_accessible = values.get("publicly_accessible")
    storage_encrypted = values.get("storage_encrypted")
    backup_retention_period = values.get("backup_retention_period")
    multi_az = values.get("multi_az")

    controls: dict[str, Any] = {}

    add_control_if_known(
        controls,
        "database_publicly_accessible",
        (
            publicly_accessible
            if isinstance(publicly_accessible, bool)
            else None
        ),
    )

    add_control_if_known(
        controls,
        "database_storage_encrypted",
        (
            storage_encrypted
            if isinstance(storage_encrypted, bool)
            else None
        ),
    )

    add_control_if_known(
        controls,
        "database_backup_retention_days",
        (
            backup_retention_period
            if isinstance(backup_retention_period, int)
            else None
        ),
    )

    add_control_if_known(
        controls,
        "database_multi_az_enabled",
        multi_az if isinstance(multi_az, bool) else None,
    )

    return {
        "id": address,
        "provider": "aws",
        "original_type": "aws_db_instance",
        "resource_type": "database",
        "controls": controls,
        "metadata": {
            "terraform_address": address,
        },
    }


def normalise_rds_instances(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        normalise_rds_instance(db_resource)
        for db_resource in find_resources_by_type(
            resources, "aws_db_instance"
        )
    ]


def normalise_aws_resources(
    resources: list[dict[str, Any]],
    references: dict[str, dict[str, list[str]]] | None = None,
) -> list[dict[str, Any]]:
    """
    Convert every currently supported AWS Terraform resource into the
    normalised infrastructure model.

    references, when provided, is the plan's configuration-expression
    map (see terraform_plan_loader.extract_configuration_references)
    used to link related resources by their actual Terraform
    dependency graph instead of only by matching resource names.
    Currently used to link an IAM role to its inline policy.

    Current support:
        - aws_s3_bucket (+ versioning, encryption, public-access,
          logging, AWS Backup coverage)
        - aws_security_group (+ its aws_lb_listener) (network)
        - aws_cloudtrail (+ its aws_cloudwatch_log_group) (logging)
        - aws_autoscaling_group (compute)
        - aws_cloudwatch_metric_alarm (monitoring)
        - aws_kms_key (encryption_key)
        - aws_db_instance (database)
        - aws_iam_role (+ its aws_iam_role_policy) (identity)
        - a plan-wide plaintext-secret sweep (secrets)
        - gdpr_* tags on any resource (governance)
        - a synthesised system-wide aggregate (processing_system)

    Related configuration resources (S3 sub-resources, CloudTrail's log
    group, an IAM role's inline policy) are not returned separately.
    They are merged into the resource they configure.
    """
    normalised_resources: list[dict[str, Any]] = []

    s3_buckets = find_resources_by_type(
        resources,
        "aws_s3_bucket",
    )

    for bucket_resource in s3_buckets:
        normalised_bucket = normalise_s3_bucket(
            bucket_resource=bucket_resource,
            all_resources=resources,
        )

        normalised_resources.append(
            normalised_bucket
        )

    normalised_resources.extend(normalise_network_perimeters(resources))
    normalised_resources.extend(normalise_cloudtrails(resources))
    normalised_resources.extend(normalise_autoscaling_groups(resources))
    normalised_resources.extend(normalise_cloudwatch_alarms(resources))
    normalised_resources.extend(normalise_kms_keys(resources))
    normalised_resources.extend(normalise_rds_instances(resources))
    normalised_resources.extend(
        normalise_iam_roles(resources, references or {})
    )
    normalised_resources.append(normalise_secrets_exposure(resources))
    normalised_resources.extend(normalise_governance_tags(resources))

    processing_system = synthesise_processing_system(
        normalised_resources
    )

    if processing_system is not None:
        normalised_resources.append(processing_system)

    return normalised_resources