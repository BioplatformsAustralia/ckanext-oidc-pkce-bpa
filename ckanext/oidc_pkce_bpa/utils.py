import json
import jwt
import logging
import requests
from typing import Any, Dict, List

import ckan.plugins.toolkit as tk
from ckan.plugins.toolkit import config as ckan_config, NotAuthorized

log = logging.getLogger(__name__)

# Required Auth0/OIDC settings
API_AUDIENCE = ckan_config.get("ckanext.oidc_pkce_bpa.api_audience")
AUTH0_DOMAIN = ckan_config.get("ckanext.oidc_pkce_bpa.auth0_domain")
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

# Defaults to your Action’s namespaced claim; allow override via ckan.ini
ROLES_CLAIM = ckan_config.get(
    "ckanext.oidc_pkce_bpa.roles_claim",
    "https://biocommons.org.au/roles",
)

TSI_ROLE = "biocommons/group/tsi"
TSI_ORG_ID = "aai-threatened-species-initiative-embargo"

# PyJWT compatibility
try:
    from jwt.algorithms import RSAAlgorithm  # PyJWT < 2.10
except ImportError:
    RSAAlgorithm = None

try:
    from jwt import PyJWKClient  # PyJWT >= 2.0
except ImportError:
    PyJWKClient = None


def extract_username(userinfo: dict) -> str:
    username_claim = ckan_config.get("ckanext.oidc_pkce_bpa.username_claim")
    username = userinfo.get(username_claim) or userinfo.get("nickname")
    if not username:
        raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")
    return username


def get_redirect_registeration_url() -> str:
    register_redirect_url = ckan_config.get("ckanext.oidc_pkce_bpa.register_redirect_url")
    if not register_redirect_url:
        raise tk.NotAuthorized("redirect_registation_url not set in ckan.ini!")
    return register_redirect_url



def _get_jwks() -> Dict[str, Any]:
    """Fetch Auth0 JWKS for RS256 verification."""
    resp = requests.get(JWKS_URL, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _get_signing_key(token: str):
    """
    Resolve signing key from JWKS.
    Supports both old (RSAAlgorithm) and new (PyJWKClient) PyJWT versions.
    """
    if RSAAlgorithm is not None:
        unverified = jwt.get_unverified_header(token)
        jwks = _get_jwks()
        for key in jwks.get("keys", []):
            if key.get("kid") == unverified.get("kid"):
                return RSAAlgorithm.from_jwk(json.dumps(key))
        raise Exception("Unable to find signing key for the token")

    if PyJWKClient is not None:
        jwk_client = PyJWKClient(JWKS_URL)
        return jwk_client.get_signing_key_from_jwt(token).key

    raise ImportError("Neither RSAAlgorithm nor PyJWKClient available; unsupported PyJWT version")


def _decode_access_token(token: Any) -> Dict[str, Any]:
    """
    Decode & verify an Auth0 access token (RS256 + JWKS).
    Returns {} on failure; callers raise if they need to.
    """
    if isinstance(token, dict):
        log.info("Token is already a dict — skipping JWT decode")
        return token
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    # Early sanity check (no verification) for clearer logs
    try:
        jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception as e:
        log.error(f"Failed to decode JWT without verification: {e}")
        return {}

    try:
        key = _get_signing_key(token)
        return jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
    except Exception as e:
        log.error(f"JWT verification failed: {e}")
        return {}


def _get_roles_from_claims(claims: Dict[str, Any]) -> List[str]:
    """
    Extract roles from the configured namespaced claim (array preferred, but
    comma/space-delimited strings tolerated).
    """
    roles: List[str] = []
    val = claims.get(ROLES_CLAIM)

    if isinstance(val, list):
        roles.extend(str(v) for v in val if v)
    elif isinstance(val, str):
        roles.extend(s for s in (x.strip() for x in val.replace(",", " ").split()) if s)

    # Deduplicate and sort for stable output
    return sorted({r for r in roles if isinstance(r, str) and r})


def get_user_roles(access_token: Any) -> List[str]:
    """
    Public helper: verify the access token and return roles from
    the namespaced claim (default: https://biocommons.org.au/roles).
    """
    if not access_token:
        raise tk.NotAuthorized("Access token is required but missing")

    claims = _decode_access_token(access_token)
    if not claims:
        raise tk.ValidationError("Unable to decode or verify access token")

    return _get_roles_from_claims(claims)


def _create_pending_membership_if_absent(*, org_id: str, user_name: str, context: Dict[str, Any]):
    """
    Idempotently create a pending membership request for user/org.
    Mirrors the snippet you provided.
    """
    try:
        existing = tk.get_action("member_requests_list")(context, {
            "object_id": org_id,
            "object_type": "organization",
            "type": "membership",
            "user": user_name,
            "status": "pending",
        })
        if existing:
            log.info("Pending request already exists for user '%s' in org '%s', skipping.", user_name, org_id)
            return

        tk.get_action("member_request_create")(context, {
            "object_id": org_id,
            "object_type": "organization",
            "type": "membership",
            "message": "Auto-created from Auth0 role biocommons/group/tsi",
        })
        log.info("Created pending membership request for '%s' in '%s' via TSI role trigger", user_name, org_id)

    except tk.ValidationError as e:
        log.warning("Validation error creating membership request for '%s': %s", org_id, e)
    except Exception as e:
        log.error("Failed to create membership request for '%s' in '%s': %s", user_name, org_id, e)


def apply_role_based_memberships(*, user_name: str, roles: List[str], context: Dict[str, Any]):
    """
    If user has 'biocommons/group/tsi', create a pending membership request
    for the 'aai-threatened-species-initiative-embargo' org (idempotent).
    """
    if not roles:
        return

    if TSI_ROLE in set(roles):
        # Ensure target org exists before attempting (avoid noise)
        try:
            tk.get_action("organization_show")(context, {"id": TSI_ORG_ID})
        except tk.ObjectNotFound:
            log.warning("Org '%s' not found in CKAN, skipping membership creation.", TSI_ORG_ID)
            return

        _create_pending_membership_if_absent(
            org_id=TSI_ORG_ID,
            user_name=user_name,
            context=context,
        )
