import logging

from datetime import datetime
from typing import Any, Dict, List

import ckan.plugins.toolkit as tk
from . import config

log = logging.getLogger(__name__)

def format_date(date_str: str) -> str:
    """
    Extracts the date portion (YYYY-MM-DD) from an ISO 8601 datetime string.
    Returns the original string if parsing fails.
    """
    try:
        return datetime.fromisoformat(date_str.replace("Z", "")).date().isoformat()
    except Exception:
        return date_str  # fallback gracefully if format is unexpected

def get_org_metadata_from_services(
    userinfo: Dict[str, Any], context: Dict[str, Any]
) -> List[Dict[str, str]]:
    """
    Extract and validate all org access metadata from ID token's app_metadata.services[].resources[].

    Returns a list of dicts with id, name, status, request_date, handling_date, handler, etc.
    """
    app_metadata = userinfo.get(config.app_metadata_claim(), {})

    services = app_metadata.get("services", [])

    org_entries = []

    for service in services:
        for resource in service.get("resources", []):
            org_id = resource.get("id")
            org_name = resource.get("name")
            status = resource.get("status")

            if not org_id:
                continue

            try:
                tk.get_action("organization_show")(context, {"id": org_id})
            except tk.ObjectNotFound:
                log.warning(f"Org '{org_id}' from app_metadata not found in CKAN, skipping.")
                continue

            org_entries.append({
                "id": org_id,
                "name": org_name,
                "status": status,
                "request_date": format_date(resource.get("initial_request_time")),
                "handling_date": format_date(resource.get("last_updated")),
                "handler": resource.get("updated_by"),
            })

    return org_entries

def sync_org_memberships_from_auth0(
    user_name: str,
    org_metadata: List[Dict[str, str]],
    context: Dict[str, Any]
):
    """
    For each approved or pending org in metadata, create a membership request
    if one does not already exist.

    Skips 'revoked' status and organizations that do not exist in CKAN.
    """
    for entry in org_metadata:
        status = entry.get("status")
        org_id = entry.get("id")

        if not org_id or status == "revoked":
            continue

        try:
            # Ensure organization exists
            tk.get_action("organization_show")(context, {"id": org_id})
        except tk.ObjectNotFound:
            log.warning(f"Organization '{org_id}' not found in CKAN, skipping.")
            continue

        try:
            existing = tk.get_action("ytp_request_list")(context, {
                "object_id": org_id,
                "object_type": "organization",
                "type": "membership",
                "user": user_name,
                "status": "pending"
            })
            if existing:
                log.info(f"Pending request already exists for user '{user_name}' in org '{org_id}', skipping.")
                continue

            tk.get_action("ytp_request_create")(context, {
                "object_id": org_id,
                "object_type": "organization",
                "type": "membership",
                "message": f"Auto-created from Auth0 login metadata with status '{status}'"
            })
            log.info(f"Created pending membership request for '{user_name}' in '{org_id}' with status '{status}'")

        except tk.ValidationError as e:
            log.warning(f"Validation error creating membership request for '{org_id}': {e}")
        except Exception as e:
            log.error(f"Failed to create membership request for '{user_name}' in '{org_id}': {e}")
