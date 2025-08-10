import json
import time
import jwt
import logging
import requests

from ckan.plugins.toolkit import config as ckan_config, NotAuthorized

from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from jwt.algorithms import RSAAlgorithm  # PyJWT < 2.10
except ImportError:
    RSAAlgorithm = None

try:
    from jwt import PyJWKClient  # PyJWT >= 2.0
except ImportError:
    PyJWKClient = None

import ckan.plugins.toolkit as tk
from . import config

log = logging.getLogger(__name__)

API_AUDIENCE = ckan_config.get("ckanext.oidc_pkce_bpa.api_audience")
AUTH0_DOMAIN = ckan_config.get("ckanext.oidc_pkce_bpa.auth0_domain")
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

MGMT_CLIENT_ID = ckan_config.get("ckanext.oidc_pkce.client_id")
MGMT_CLIENT_SECRET = ckan_config.get("ckanext.oidc_pkce.client_secret")

# very small in-proc cache for the M2M token
_MGMT_CACHE: Dict[str, Any] = {"token": None, "exp": 0}

def extract_username(userinfo: dict) -> str:
    username_claim = config.username_claim()
    username = userinfo.get(username_claim) or userinfo.get("nickname")
    if not username:
        raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")
    return username


def format_date(date_str: str) -> str:
    """
    Extracts the date portion (YYYY-MM-DD) from an ISO 8601 datetime string.
    Returns the original string if parsing fails.
    """
    try:
        return datetime.fromisoformat(date_str.replace("Z", "")).date().isoformat()
    except Exception:
        return date_str  # fallback gracefully if format is unexpected


def get_jwks() -> Dict[str, Any]:
    """Fetch the JSON Web Key Set (JWKS) from Auth0 to validate JWTs."""
    response = requests.get(JWKS_URL, timeout=10)
    response.raise_for_status()
    return response.json()


def get_signing_key(token: str):
    """
    Return signing key from Auth0's JWKS.
    Supports both old (RSAAlgorithm) and new (PyJWKClient) PyJWT versions.
    """
    # Old PyJWT path
    if RSAAlgorithm is not None:
        unverified_header = jwt.get_unverified_header(token)
        jwks = get_jwks()
        for key in jwks.get("keys", []):
            if key.get("kid") == unverified_header.get("kid"):
                return RSAAlgorithm.from_jwk(json.dumps(key))
        raise Exception("Unable to find signing key for the token")

    # New PyJWT path
    if PyJWKClient is not None:
        jwk_client = PyJWKClient(JWKS_URL)
        return jwk_client.get_signing_key_from_jwt(token).key

    raise ImportError("Neither RSAAlgorithm nor PyJWKClient available; unsupported PyJWT version")


def decode_access_token(token: Any) -> Dict[str, Any]:
    """
    Decode and verify a JWT token using RS256 and JWKS.
    Returns {} on failure.
    """
    if isinstance(token, dict):
        log.info(" Token is already a dict — skipping JWT decode")
        return token

    if isinstance(token, bytes):
        token = token.decode("utf-8")

    try:
        # Decode without verification first to inspect
        _ = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception as e:
        log.error(f" Failed to decode JWT without verification: {e}")
        return {}

    try:
        key = get_signing_key(token)
        log.info(" Successfully resolved signing key for JWT.")

        decoded = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        log.info(" Verified decoded JWT claims")
        return decoded
    except Exception as e:
        log.error(f"JWT decoding failed: {e}")
        return {}


def _now() -> int:
    return int(time.time())


def get_management_token() -> Optional[str]:
    """
    Client-credentials grant for Auth0 Management API.
    Caches token briefly to avoid rate limits.
    """
    if not (MGMT_CLIENT_ID and MGMT_CLIENT_SECRET and API_AUDIENCE):
        log.warning("Management API credentials not configured; skipping")
        return None

    tok = _MGMT_CACHE.get("token")
    exp = _MGMT_CACHE.get("exp", 0)
    if tok and _now() < exp:
        return tok

    try:
        r = requests.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "client_id": MGMT_CLIENT_ID,
                "client_secret": MGMT_CLIENT_SECRET,
                "audience": API_AUDIENCE,
                "grant_type": "client_credentials",
            },
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        tok = data["access_token"]
        # Default lifetime is large; keep a conservative 10-minute cache
        _MGMT_CACHE["token"] = tok
        _MGMT_CACHE["exp"] = _now() + 600
        return tok
    except Exception as e:
        log.error(f"Failed to obtain Management API token: {e}")
        return None


def get_user_app_metadata(sub: str) -> Dict[str, Any]:
    """
    Fetch app_metadata via Auth0 Management API.
    """
    token = get_management_token()
    if not token:
        return {}

    try:
        r = requests.get(
            f"https://{AUTH0_DOMAIN}/api/v2/users/{sub}",
            params={"fields": "app_metadata,user_id"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get("app_metadata") or {}
    except Exception as e:
        log.error(f"Failed to fetch user app_metadata via Management API: {e}")
        return {}


def _services_to_org_entries(services: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Convert services[].resources[] to the flattened org entries used by UI/ytp-request.
    Validates that the CKAN org exists before including it.
    """
    org_entries: List[Dict[str, str]] = []
    for service in services or []:
        for resource in service.get("resources", []) or []:
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


def get_org_metadata_from_services(
    app_metadata: Dict[str, Any], context: Dict[str, Any]
) -> List[Dict[str, str]]:
    """
    Extract and validate org access metadata.

    Accepts a raw app_metadata dict (already extracted).

    Returns a list of dicts with id, name, status, request_date, handling_date, handler, etc.
    """
    claim_key = config.app_metadata_claim()  # e.g. "https://biocommons.org.au/app_metadata"

    # If we were passed decoded access-token claims, pull the namespaced claim.
    if isinstance(app_metadata, dict) and claim_key in (app_metadata or {}):
        app_metadata = (app_metadata or {}).get(claim_key, {}) or {}
    else:
        # Otherwise, assume we were passed the raw app_metadata dict itself.
        app_metadata = app_metadata or {}

    services = (app_metadata or {}).get("services", [])
    return _services_to_org_entries(services, context)


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

