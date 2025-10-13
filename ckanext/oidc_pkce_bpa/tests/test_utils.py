import json

import pytest
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce_bpa import utils
from ckan import model


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


def test_get_redirect_registeration_url_present(auth0_config):
    assert utils.get_redirect_registeration_url() == "http://example.com/register"


def test_get_redirect_registeration_url_missing(monkeypatch):
    monkeypatch.setattr(utils, "ckan_config", {})
    with pytest.raises(tk.NotAuthorized, match="redirect_registation_url"):
        utils.get_redirect_registeration_url()


def test_role_org_mapping_is_normalised(auth0_config):
    settings = utils.get_auth0_settings()
    assert settings.role_org_mapping["tsi-member"] == ("org-123", "org-456")
    assert settings.role_org_mapping["duplicate-role"] == ("org-123",)

    # Ensure mapping is read-only to callers
    with pytest.raises(TypeError):
        settings.role_org_mapping["duplicate-role"] = ("org-123", "org-456")


def test_membership_service_recognises_existing_members_by_id(monkeypatch, auth0_config):
    """Ensure we skip creating duplicate memberships when CKAN returns user IDs."""
    user = model.User(name="memberuser", email="member@example.com", password="")
    model.Session.add(user)
    model.Session.commit()

    user_id = user.id
    model.Session.remove()

    members_called = []

    def fake_get_action(name):
        if name == "member_list":
            return lambda context, data: [(user_id, "user", "member")]
        if name == "member_create":
            return lambda context, data: members_called.append(data)
        raise AssertionError(f"Unexpected action {name}")

    monkeypatch.setattr(utils.tk, "get_action", fake_get_action)

    service = utils.MembershipService(utils.get_auth0_settings())
    service.apply_role_based_memberships(
        user_name=user.name,
        roles=["tsi-member"],
        context={"model": model},
    )

    assert members_called == []

    model.Session.query(model.User).filter_by(name="memberuser").delete()
    model.Session.commit()
