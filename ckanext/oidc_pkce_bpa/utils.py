import logging
from typing import Any, Dict, List

import ckan.plugins.toolkit as tk
from . import config

log = logging.getLogger(__name__)


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
                "request_date": resource.get("initial_request_time"),
                "handling_date": resource.get("last_updated"),
                "handler": resource.get("updated_by"),
            })

    return org_entries
