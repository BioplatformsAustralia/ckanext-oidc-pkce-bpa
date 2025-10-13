import ast
import json
import jwt
import logging
import requests
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from types import MappingProxyType

import ckan.plugins.toolkit as tk
from ckan.plugins.toolkit import config as ckan_config, NotAuthorized
from ckan import model as ckan_model

log = logging.getLogger(__name__)


def _require_config_value(*, key: str) -> str:
    value = ckan_config.get(key)
    if not value:
        raise tk.NotAuthorized(f"Missing '{key}' configuration")
    return value


def _require_role_org_mapping(*, key: str) -> Mapping[str, Tuple[str, ...]]:
    raw_value = _require_config_value(key=key)

    def _load_mapping(value: str) -> Dict[str, Any]:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            try:
                return ast.literal_eval(value)
            except (ValueError, SyntaxError) as exc:
                raise tk.NotAuthorized(
                    f"Configuration '{key}' must be valid JSON or Python literal syntax"
                ) from exc

    parsed = _load_mapping(raw_value)
    if not isinstance(parsed, dict):
        raise tk.NotAuthorized(f"Configuration '{key}' must be a mapping of role → organizations")

    normalised: Dict[str, Tuple[str, ...]] = {}
    for role, orgs in parsed.items():
        if not isinstance(role, str) or not role.strip():
            raise tk.NotAuthorized(
                f"Configuration '{key}' must use non-empty strings for role names"
            )

        org_id_list: Iterable[Any]
        if isinstance(orgs, str):
            org_id_list = [orgs]
        elif isinstance(orgs, Mapping):
            raise tk.NotAuthorized(
                f"Configuration '{key}' must map role '{role}' to a sequence of organisation ids, not a mapping"
            )
        elif isinstance(orgs, Iterable):
            org_id_list = orgs
        else:
            raise tk.NotAuthorized(
                f"Configuration '{key}' must map role '{role}' to a string or iterable of strings"
            )

        unique_orgs: List[str] = []
        seen = set()
        for org in org_id_list:
            if not isinstance(org, str) or not org.strip():
                raise tk.NotAuthorized(
                    f"Configuration '{key}' has an invalid organization id for role '{role}'"
                )
            cleaned = org.strip()
            if cleaned in seen:
                continue
            seen.add(cleaned)
            unique_orgs.append(cleaned)

        if not unique_orgs:
            log.warning(
                "Role '%s' in configuration '%s' does not list any organisations; skipping.",
                role,
                key,
            )
            continue

        normalised[role] = tuple(unique_orgs)

    if not normalised:
        log.warning(
            "Configuration '%s' did not yield any role → organisation mappings.",
            key,
        )

    return MappingProxyType(normalised)


@dataclass(frozen=True, eq=False)
class Auth0Settings:
    api_audience: str
    auth0_domain: str
    roles_claim: str
    role_org_mapping: Mapping[str, Tuple[str, ...]]
    username_claim: str

    @property
    def issuer(self) -> str:
        return f"https://{self.auth0_domain}/"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}.well-known/jwks.json"


@lru_cache(maxsize=1)
def get_auth0_settings() -> Auth0Settings:
    return Auth0Settings(
        api_audience=_require_config_value(key="ckanext.oidc_pkce_bpa.api_audience"),
        auth0_domain=_require_config_value(key="ckanext.oidc_pkce_bpa.auth0_domain"),
        roles_claim=_require_config_value(key="ckanext.oidc_pkce_bpa.roles_claim"),
        role_org_mapping=_require_role_org_mapping(key="ckanext.oidc_pkce_bpa.role_org_mapping"),
        username_claim=_require_config_value(key="ckanext.oidc_pkce_bpa.username_claim"),
    )

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
    settings = get_auth0_settings()
    username = userinfo.get(settings.username_claim) or userinfo.get("nickname")
    if not username:
        raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")
    return username


def get_redirect_registration_url() -> str:
    register_redirect_url = ckan_config.get("ckanext.oidc_pkce_bpa.register_redirect_url")
    if not register_redirect_url:
        raise tk.NotAuthorized("redirect_registation_url not set in ckan.ini!")
    return register_redirect_url


def get_site_context() -> Dict[str, Any]:
    """Return an action context that runs as the CKAN site user."""
    site_user = tk.get_action("get_site_user")({"ignore_auth": True}, {})
    if not site_user or not site_user.get("name"):
        raise tk.NotAuthorized("Site user account is not configured")

    return {
        "ignore_auth": True,
        "user": site_user["name"],
        "model": ckan_model,
        "session": ckan_model.Session,
    }


@lru_cache(maxsize=1)
def _cached_jwks(url: str) -> Dict[str, Any]:
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


@lru_cache(maxsize=1)
def _cached_jwk_client(url: str):
    if PyJWKClient is None:
        return None
    return PyJWKClient(url)


class Auth0TokenService:
    def __init__(self, settings: Auth0Settings):
        self._settings = settings

    def _get_jwks(self) -> Dict[str, Any]:
        return _cached_jwks(self._settings.jwks_url)

    def _get_signing_key(self, token: str):
        if RSAAlgorithm is not None:
            unverified = jwt.get_unverified_header(token)
            jwks = self._get_jwks()
            for key in jwks.get("keys", []):
                if key.get("kid") == unverified.get("kid"):
                    return RSAAlgorithm.from_jwk(json.dumps(key))
            raise Exception("Unable to find signing key for the token")

        if PyJWKClient is not None:
            jwk_client = _cached_jwk_client(self._settings.jwks_url)
            if jwk_client is None:
                raise ImportError("PyJWKClient unavailable for token verification")
            return jwk_client.get_signing_key_from_jwt(token).key

        raise ImportError("Neither RSAAlgorithm nor PyJWKClient available; unsupported PyJWT version")

    def decode_access_token(self, token: Any) -> Dict[str, Any]:
        if isinstance(token, dict):
            log.info("Token is already a dict — skipping JWT decode")
            return token
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        try:
            jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        except Exception as exc:
            log.error("Failed to decode JWT without verification: %s", exc)
            return {}

        try:
            key = self._get_signing_key(token)
            return jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=self._settings.api_audience,
                issuer=self._settings.issuer,
            )
        except Exception as exc:
            log.error("JWT verification failed: %s", exc)
            return {}

    def get_user_roles(self, token: Any) -> List[str]:
        claims = self.decode_access_token(token)
        if not claims:
            return []
        return self._extract_roles_from_claims(claims)

    def _extract_roles_from_claims(self, claims: Dict[str, Any]) -> List[str]:
        roles: List[str] = []
        val = claims.get(self._settings.roles_claim)

        if isinstance(val, list):
            roles.extend(str(v) for v in val if v)
        elif isinstance(val, str):
            roles.extend(s for s in (item.strip() for item in val.replace(",", " ").split()) if s)

        return sorted({r for r in roles if isinstance(r, str) and r})


@lru_cache(maxsize=1)
def get_token_service() -> Auth0TokenService:
    return Auth0TokenService(get_auth0_settings())


class MembershipService:
    def __init__(self, settings: Auth0Settings):
        self._settings = settings

    def apply_role_based_memberships(self, *, user_name: str, roles: List[str], context: Dict[str, Any]):
        if not roles:
            return

        seen_org_ids = set()
        for role in roles:
            org_ids = self._settings.role_org_mapping.get(role)
            if not org_ids:
                log.debug("No organisation mapping defined for role '%s'", role)
                continue

            for org_id in org_ids:
                if org_id in seen_org_ids:
                    continue
                seen_org_ids.add(org_id)
                self._ensure_org_member(org_id=org_id, user_name=user_name, context=context)

    def _ensure_org_member(self, *, org_id: str, user_name: str, context: Dict[str, Any]):
        try:
            members = tk.get_action("member_list")(context, {"id": org_id, "object_type": "user"})
            if any(self._member_entry_matches_user(member, user_name) for member in members):
                log.info("User '%s' already a member of '%s'; skipping.", user_name, org_id)
                return
            tk.get_action("member_create")(context, {
                "id": org_id,
                "object": user_name,
                "object_type": "user",
                "capacity": "member"
            })
            log.info("Granted '%s' access to org '%s' with capacity 'member'", user_name, org_id)
        except NotAuthorized as exc:
            log.error("NotAuthorized adding '%s' to '%s': %s (tip: use site user context)", user_name, org_id, exc)
            raise
        except tk.ValidationError as exc:
            log.warning("Validation error adding '%s' to '%s': %s", user_name, org_id, exc)
        except Exception as exc:
            log.error("Failed to add '%s' to '%s': %s", user_name, org_id, exc)

    @staticmethod
    def _member_entry_matches_user(member: Any, user_name: str) -> bool:
        if isinstance(member, dict):
            for key in ("username", "name", "id", "object", "user"):
                if member.get(key) == user_name:
                    return True
            return False

        if isinstance(member, (list, tuple)):
            return any(isinstance(item, str) and item == user_name for item in member)

        return False


@lru_cache(maxsize=1)
def get_membership_service() -> MembershipService:
    return MembershipService(get_auth0_settings())


def get_user_roles(token: Any) -> List[str]:
    return get_token_service().get_user_roles(token)


def apply_role_based_memberships(*, user_name: str, roles: List[str], context: Dict[str, Any]):
    get_membership_service().apply_role_based_memberships(user_name=user_name, roles=roles, context=context)
