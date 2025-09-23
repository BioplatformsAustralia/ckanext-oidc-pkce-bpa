from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from ckan import model
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce_bpa import utils
from ckanext.oidc_pkce_bpa.plugin import OidcPkceBpaPlugin


@pytest.fixture
def plugin():
    """Initialise the plugin once per test."""
    return OidcPkceBpaPlugin()


@pytest.fixture
def clean_session():
    """Ensure SQLAlchemy session state is cleaned between tests."""
    yield
    model.Session.remove()


@pytest.fixture
def mock_config(monkeypatch):
    """Provide the Auth0-related configuration expected by utils."""
    fake_cfg = {
        "ckanext.oidc_pkce_bpa.api_audience": "test-audience",
        "ckanext.oidc_pkce_bpa.auth0_domain": "auth0.example.com",
        "ckanext.oidc_pkce_bpa.roles_claim": "https://example.com/roles",
        "ckanext.oidc_pkce_bpa.tsi_role": "tsi-member",
        "ckanext.oidc_pkce_bpa.tsi_org_id": "org-123",
        "ckanext.oidc_pkce_bpa.username_claim": "https://biocommons.org.au/username",
        "ckanext.oidc_pkce_bpa.register_redirect_url": "https://example.com/register",
    }

    utils.get_auth0_settings.cache_clear()
    monkeypatch.setattr(utils, "ckan_config", fake_cfg, raising=False)
    monkeypatch.setattr(tk, "config", fake_cfg, raising=False)
    yield fake_cfg
    utils.get_auth0_settings.cache_clear()


@pytest.fixture
def mock_services(monkeypatch, mock_config):
    """Stub out token and membership services to avoid external effects."""
    utils.get_token_service.cache_clear()
    utils.get_membership_service.cache_clear()

    token_service = MagicMock()
    token_service.get_user_roles.return_value = ["tsi-member"]

    membership_service = MagicMock()
    site_context = {"ignore_auth": True, "user": "site_user"}

    monkeypatch.setattr(utils, "get_token_service", lambda: token_service)
    monkeypatch.setattr(utils, "get_membership_service", lambda: membership_service)
    monkeypatch.setattr(utils, "get_site_context", lambda: site_context)

    return SimpleNamespace(
        token_service=token_service,
        membership_service=membership_service,
        site_context=site_context,
    )


def test_create_new_user(plugin, clean_session, mock_services):
    """A new CKAN user is created and synced with membership roles."""
    userinfo = {
        "sub": "auth0|123",
        "email": "newuser@example.com",
        "name": "New User",
        "https://biocommons.org.au/username": "newuser",
        "access_token": "token-123",
    }

    user = plugin.get_oidc_user(userinfo)

    assert user.name == "newuser"
    assert user.email == "newuser@example.com"
    assert user.fullname == "New User"
    assert user.plugin_extras["oidc_pkce"]["auth0_id"] == "auth0|123"
    mock_services.token_service.get_user_roles.assert_called_once_with("token-123")
    mock_services.membership_service.apply_role_based_memberships.assert_called_once_with(
        user_name="newuser",
        roles=["tsi-member"],
        context=mock_services.site_context,
    )


def test_existing_user_backfill_auth0(plugin, clean_session, mock_services):
    """Existing users receive a backfilled Auth0 ID and membership sync."""
    user = model.User(
        name="existinguser",
        email="existing@example.com",
        fullname="Existing User",
        password="",
    )
    model.Session.add(user)
    model.Session.commit()

    user.plugin_extras = {}
    model.Session.commit()

    userinfo = {
        "sub": "auth0|456",
        "email": "existing@example.com",
        "name": "Existing User",
        "https://biocommons.org.au/username": "existinguser",
        "access_token": "token-456",
    }

    updated_user = plugin.get_oidc_user(userinfo)

    assert updated_user.plugin_extras["oidc_pkce"]["auth0_id"] == "auth0|456"
    mock_services.token_service.get_user_roles.assert_called_once_with("token-456")
    mock_services.membership_service.apply_role_based_memberships.assert_called_once_with(
        user_name="existinguser",
        roles=["tsi-member"],
        context=mock_services.site_context,
    )


def test_existing_user_update_fullname(plugin, clean_session, mock_services):
    """Full name changes from Auth0 propagate to existing CKAN users."""
    user = model.User(
        name="fullnameuser",
        email="full@example.com",
        fullname="Old Name",
        password="",
    )
    user.plugin_extras = {"oidc_pkce": {"auth0_id": "auth0|789"}}
    model.Session.add(user)
    model.Session.commit()

    userinfo = {
        "sub": "auth0|789",
        "email": "full@example.com",
        "name": "New Name",
        "https://biocommons.org.au/username": "fullnameuser",
        "access_token": "token-789",
    }

    updated_user = plugin.get_oidc_user(userinfo)

    assert updated_user.fullname == "New Name"
    mock_services.token_service.get_user_roles.assert_called_once_with("token-789")
    mock_services.membership_service.apply_role_based_memberships.assert_called_once_with(
        user_name="fullnameuser",
        roles=["tsi-member"],
        context=mock_services.site_context,
    )


def test_missing_sub_raises(plugin):
    """Missing `sub` is rejected before any downstream work is attempted."""
    userinfo = {
        "email": "missing@example.com",
        "https://biocommons.org.au/username": "someuser",
    }

    with pytest.raises(tk.NotAuthorized, match="sub"):
        plugin.get_oidc_user(userinfo)


def test_missing_username_raises(plugin, mock_services):
    """Missing username claim bubbles up as a NotAuthorized error."""
    userinfo = {
        "sub": "auth0|999",
        "email": "missing@example.com",
        "access_token": "token-999",
    }

    with pytest.raises(tk.NotAuthorized, match="Missing 'username' in Auth0 ID token"):
        plugin.get_oidc_user(userinfo)

    mock_services.token_service.get_user_roles.assert_not_called()


def test_missing_access_token_raises(plugin, mock_services):
    """Access tokens are mandatory so that role membership stays in sync."""
    userinfo = {
        "sub": "auth0|555",
        "email": "person@example.com",
        "https://biocommons.org.au/username": "person",
    }

    with pytest.raises(tk.ValidationError, match="No access token"):
        plugin.get_oidc_user(userinfo)

    mock_services.token_service.get_user_roles.assert_not_called()
    mock_services.membership_service.apply_role_based_memberships.assert_not_called()


def test_blueprint_routes(plugin, mock_config, monkeypatch):
    """Blueprint routes perform the expected redirects."""
    blueprint = plugin.get_blueprint()

    register_view = blueprint.view_functions["oidc_pkce_bpa.force_oidc_register"]
    response = register_view()
    assert response.status_code == 302
    assert response.location == "https://example.com/register"

    monkeypatch.setattr(tk, "redirect_to", lambda endpoint: f"redirect:{endpoint}")
    login_view = blueprint.view_functions["oidc_pkce_bpa.force_oidc_login"]
    assert login_view() == "redirect:oidc_pkce.login"
