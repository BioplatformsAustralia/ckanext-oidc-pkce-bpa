import json

import pytest
import ckan.plugins.toolkit as tk
from types import SimpleNamespace

from ckanext.oidc_pkce_bpa import utils


@pytest.fixture
def auth0_config(monkeypatch):
    """Seed the configuration needed for Auth0 settings resolution."""
    config = {
        "ckanext.oidc_pkce_bpa.api_audience": "test-audience",
        "ckanext.oidc_pkce_bpa.auth0_domain": "auth0.example.com",
        "ckanext.oidc_pkce_bpa.roles_claim": "https://example.com/roles",
        "ckanext.oidc_pkce_bpa.role_org_mapping": json.dumps(
            {
                "tsi-member": ["org-123", "org-456"],
                "duplicate-role": ["org-123", "org-123"],
            }
        ),
        "ckanext.oidc_pkce_bpa.username_claim": "claim_key",
        "ckanext.oidc_pkce_bpa.register_redirect_url": "http://example.com/register",
    }

    utils.get_auth0_settings.cache_clear()
    monkeypatch.setattr(utils, "ckan_config", config, raising=False)
    monkeypatch.setattr(tk, "config", config, raising=False)
    yield config
    utils.get_auth0_settings.cache_clear()


def test_extract_username_from_claim(auth0_config):
    claim_key = auth0_config["ckanext.oidc_pkce_bpa.username_claim"]
    userinfo = {claim_key: "theuser"}
    assert utils.extract_username(userinfo) == "theuser"


def test_extract_username_fallback_and_missing(auth0_config):
    # Falls back to nickname when the configured claim is absent.
    assert utils.extract_username({"nickname": "nick"}) == "nick"

    # Missing both claim and nickname -> raises
    with pytest.raises(tk.NotAuthorized, match="username"):
        utils.extract_username({})


def test_get_redirect_registration_url_present(auth0_config):
    assert utils.get_redirect_registration_url() == "http://example.com/register"


def test_get_redirect_registration_url_missing(monkeypatch):
    monkeypatch.setattr(utils, "ckan_config", {})
    with pytest.raises(tk.NotAuthorized, match="redirect_registation_url"):
        utils.get_redirect_registration_url()


def test_role_org_mapping_is_normalised(auth0_config):
    settings = utils.get_auth0_settings()
    assert settings.role_org_mapping["tsi-member"] == ("org-123", "org-456")
    assert settings.role_org_mapping["duplicate-role"] == ("org-123",)

    # Ensure mapping is read-only to callers
    with pytest.raises(TypeError):
        settings.role_org_mapping["duplicate-role"] = ("org-123", "org-456")


def _make_membership_actions(memberships, id_lookup=None):
    id_lookup = id_lookup or {}
    reverse_lookup = {v: k for k, v in id_lookup.items()}

    def member_list(context, data):
        return memberships.get(data["id"], [])

    def member_create(context, data):
        org_members = memberships.setdefault(data["id"], [])
        identifier = data["object"]
        if identifier in reverse_lookup:
            username = reverse_lookup[identifier]
            user_id = identifier
        else:
            username = identifier
            user_id = id_lookup.get(identifier, identifier)
        org_members.append({"id": user_id, "username": username})
        return {"success": True}

    def member_delete(context, data):
        org_members = memberships.get(data["id"], [])
        identifier = data["object"]
        if identifier in reverse_lookup:
            username = reverse_lookup[identifier]
            user_id = identifier
        else:
            username = identifier
            user_id = id_lookup.get(identifier, identifier)
        memberships[data["id"]] = [
            member
            for member in org_members
            if member.get("username") != username and member.get("id") != user_id
        ]
        return {"success": True}

    return {
        "member_list": member_list,
        "member_create": member_create,
        "member_delete": member_delete,
    }


def test_membership_service_adds_and_removes_roles(auth0_config, monkeypatch):
    memberships = {
        "org-123": [],
        "org-456": [],
    }
    id_lookup = {"alice": "user-id-alice"}

    def fake_get(cls, username):
        return SimpleNamespace(id=id_lookup.get(username), name=username)

    monkeypatch.setattr(utils.ckan_model.User, "get", classmethod(fake_get), raising=False)

    actions = _make_membership_actions(memberships, id_lookup)
    monkeypatch.setattr(utils.tk, "get_action", lambda name: actions[name])
    service = utils.MembershipService(utils.get_auth0_settings())

    service.apply_role_based_memberships(user_name="alice", roles=["tsi-member"], context={})

    assert memberships["org-123"] == [{"id": "user-id-alice", "username": "alice"}]
    assert memberships["org-456"] == [{"id": "user-id-alice", "username": "alice"}]

    service.apply_role_based_memberships(user_name="alice", roles=[], context={})

    assert memberships["org-123"] == []
    assert memberships["org-456"] == []


def test_membership_service_skips_unmanaged_orgs(auth0_config, monkeypatch):
    memberships = {
        "org-123": [{"id": "user-id-alice", "username": "alice"}],
        "org-999": [{"id": "user-id-alice", "username": "alice"}],
    }
    delete_calls = []
    id_lookup = {"alice": "user-id-alice"}
    reverse_lookup = {v: k for k, v in id_lookup.items()}

    def fake_get(cls, username):
        return SimpleNamespace(id=id_lookup.get(username), name=username)

    monkeypatch.setattr(utils.ckan_model.User, "get", classmethod(fake_get), raising=False)

    def member_delete(context, data):
        delete_calls.append(data["id"])
        org_members = memberships.get(data["id"], [])
        identifier = data["object"]
        username = reverse_lookup.get(identifier, identifier)
        memberships[data["id"]] = [
            member
            for member in org_members
            if member.get("username") != username and member.get("id") != identifier
        ]

    actions = _make_membership_actions(memberships, id_lookup)
    actions["member_delete"] = member_delete
    monkeypatch.setattr(utils.tk, "get_action", lambda name: actions[name])

    service = utils.MembershipService(utils.get_auth0_settings())
    service.apply_role_based_memberships(user_name="alice", roles=[], context={})

    assert "org-123" in delete_calls
    assert "org-999" not in delete_calls
