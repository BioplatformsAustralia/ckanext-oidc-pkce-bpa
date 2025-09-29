import json
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest
from flask import Flask, redirect
from ckan import model
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce_bpa import utils
from ckanext.oidc_pkce_bpa.plugin import OidcPkceBpaPlugin
import ckanext.oidc_pkce_bpa.plugin as plugin_module
from ckanext.oidc_pkce import views as oidc_views


@pytest.fixture
def plugin():
    """Initialise the plugin once per test."""
    plugin_module._ORIGINAL_FORCE_LOGIN = None
    plugin_module._ORIGINAL_OIDC_LOGIN = None
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
        "ckanext.oidc_pkce_bpa.role_org_mapping": json.dumps({"tsi-member": ["org-123"]}),
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
    app = Flask(__name__)
    app.register_blueprint(blueprint)

    monkeypatch.setattr(tk, "redirect_to", lambda endpoint: redirect(f"/mock/{endpoint}"))

    client = app.test_client()

    register_response = client.get("/user/register")
    assert register_response.status_code == 302
    assert register_response.headers["Location"] == "https://example.com/register"

    login_response = client.get("/user/login")
    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/mock/oidc_pkce.login")


def test_oidc_login_response_passthrough_user(plugin):
    """When CKAN user sync succeeds we allow the default flow to continue."""
    user = model.User(name="passthrough", password="dummy")
    assert plugin.oidc_login_response(user) is None


def test_oidc_login_response_redirects_home(plugin, monkeypatch):
    """Unverified email keeps users on CKAN instead of re-triggering OIDC."""
    fake_session = {
        plugin_module.SESSION_CAME_FROM: "original",
        plugin_module.SESSION_STATE: "state",
        "other": "value",
    }

    monkeypatch.setattr(plugin_module, "session", fake_session, raising=False)
    monkeypatch.setattr(tk, "redirect_to", lambda endpoint: f"/mock/{endpoint}")

    response = SimpleNamespace(status_code=302, location="/")

    result = plugin.oidc_login_response(response)

    assert result == "/mock/home.index"
    assert plugin_module.SESSION_CAME_FROM not in fake_session
    assert plugin_module.SESSION_STATE not in fake_session
    assert plugin_module.SESSION_SKIP_OIDC not in fake_session


def test_callback_access_denied_redirects_home(monkeypatch):
    """The patched callback keeps denial errors on CKAN rather than Auth0."""
    messages = []
    monkeypatch.setattr(
        tk,
        "h",
        SimpleNamespace(flash_error=lambda msg: messages.append(msg)),
        raising=False,
    )
    monkeypatch.setattr(
        tk,
        "redirect_to",
        lambda endpoint: redirect(f"/mock/{endpoint}"),
    )

    app = Flask(__name__)
    app.secret_key = "testing"
    app.register_blueprint(oidc_views.bp)

    client = app.test_client()

    with client.session_transaction() as sess:
        sess[plugin_module.SESSION_CAME_FROM] = "original"
        sess[plugin_module.SESSION_STATE] = "state"
        sess[plugin_module.SESSION_VERIFIER] = "verifier"

    response = client.get(
        "/user/login/oidc-pkce/callback?error=access_denied&error_description="
        "Email%20not%20verified"
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mock/home.index")
    assert messages[-1] == (
        "Your email address is not verified. Please check your inbox, confirm your "
        "email address and sign in again."
    )

    with client.session_transaction() as sess:
        assert plugin_module.SESSION_CAME_FROM not in sess
        assert plugin_module.SESSION_STATE not in sess
        assert plugin_module.SESSION_VERIFIER not in sess
        assert sess[plugin_module.SESSION_FORCE_PROMPT] is True
        assert plugin_module.SESSION_SKIP_OIDC not in sess




def test_force_login_triggers_prompt_when_flagged(monkeypatch):
    """SSO denial forces the next login attempt to show the Auth0 prompt."""
    monkeypatch.setattr(plugin_module.oidc_config, "client_id", lambda: "cid")
    monkeypatch.setattr(plugin_module.oidc_config, "redirect_url", lambda: "https://ckan.example.com/callback")
    monkeypatch.setattr(plugin_module.oidc_config, "scope", lambda: "openid profile email")
    monkeypatch.setattr(plugin_module.oidc_config, "auth_url", lambda: "https://auth.example.com/authorize")
    monkeypatch.setattr(plugin_module.oidc_utils, "code_verifier", lambda: "verifier")
    monkeypatch.setattr(plugin_module.oidc_utils, "app_state", lambda: "appstate")
    monkeypatch.setattr(plugin_module.oidc_utils, "code_challenge", lambda _verifier: "challenge")

    app = Flask(__name__)
    app.secret_key = "testing"
    app.register_blueprint(oidc_views.bp)

    client = app.test_client()

    with client.session_transaction() as sess:
        sess[plugin_module.SESSION_FORCE_PROMPT] = True

    response = client.get("/user/login?came_from=/dataset")
    assert response.status_code == 302

    parsed = urlparse(response.headers["Location"])
    query = parse_qs(parsed.query)
    assert query.get("prompt") == ["login"]
    assert query.get("state") == ["appstate"]
    assert query.get("code_challenge") == ["challenge"]

    with client.session_transaction() as sess:
        assert plugin_module.SESSION_FORCE_PROMPT not in sess
        assert sess[plugin_module.SESSION_STATE] == "appstate"
        assert sess[plugin_module.SESSION_CAME_FROM] == "/dataset"
        assert sess[plugin_module.SESSION_VERIFIER] == "verifier"


def test_login_route_always_redirects_to_oidc(monkeypatch):
    """The login route keeps redirecting to the OIDC flow even if legacy flags exist."""
    monkeypatch.setattr(tk, "redirect_to", lambda endpoint: f"/mock/{endpoint}")

    app = Flask(__name__)
    app.secret_key = "testing"
    app.register_blueprint(oidc_views.bp)

    client = app.test_client()

    with client.session_transaction() as sess:
        sess[plugin_module.SESSION_SKIP_OIDC] = True

    response = client.get("/user/login")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mock/oidc_pkce.login")
