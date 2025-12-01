import json
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest
from flask import Flask, g, redirect, url_for
from ckan import model
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce_bpa import utils
from ckanext.oidc_pkce_bpa.plugin import OidcPkceBpaPlugin
import ckanext.oidc_pkce_bpa.plugin as plugin_module
from ckanext.oidc_pkce import views as oidc_views


def register_oidc_blueprint(app):
    """Register the core OIDC blueprint and re-apply BPA overrides for each test app."""
    app.register_blueprint(oidc_views.bp)
    app.register_blueprint(plugin_module.public_bp)
    app.register_blueprint(plugin_module.admin_bp)

    def _fallback_force_login():
        return tk.redirect_to("oidc_pkce.login")

    route_factories = [
        ("/user/login", "oidc_pkce.force_oidc_login", getattr(oidc_views, "force_oidc_login", _fallback_force_login)),
        ("/user/login/oidc-pkce", "oidc_pkce.login", getattr(oidc_views, "login", lambda: tk.redirect_to("home.index"))),
    ]

    for rule, endpoint, view in route_factories:
        if endpoint not in app.view_functions:
            app.add_url_rule(rule, endpoint=endpoint, view_func=view)

    plugin_module._register_callback_override(SimpleNamespace(app=app))


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
        "ckanext.oidc_pkce_bpa.profile_redirect_url": "https://profiles.example.com/profile",
        "ckanext.oidc_pkce_bpa.support_email": "support@example.com",
    }

    utils.get_auth0_settings.cache_clear()
    monkeypatch.setattr(utils, "ckan_config", fake_cfg, raising=False)
    monkeypatch.setattr(tk, "config", fake_cfg, raising=False)
    yield fake_cfg
    utils.get_auth0_settings.cache_clear()


def test_update_config_requires_support_email(monkeypatch, plugin):
    """Plugin startup fails fast when the support email config is missing."""
    monkeypatch.setattr(tk, "config", {}, raising=False)
    monkeypatch.setattr(tk, "add_template_directory", lambda *_args, **_kwargs: None)

    with pytest.raises(tk.ValidationError, match=plugin_module.SUPPORT_EMAIL_CONFIG_KEY):
        plugin.update_config({})


def test_update_config_registers_templates(monkeypatch, plugin):
    """Template directory registration still occurs when config is valid."""
    fake_cfg = {plugin_module.SUPPORT_EMAIL_CONFIG_KEY: "help@example.com"}
    monkeypatch.setattr(tk, "config", fake_cfg, raising=False)

    captured = {}

    def _fake_add_template_directory(cfg, directory):
        captured["args"] = (cfg, directory)

    monkeypatch.setattr(tk, "add_template_directory", _fake_add_template_directory)

    plugin.update_config("config_object")

    assert captured["args"] == ("config_object", "templates")


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


@pytest.fixture
def flash_messages(monkeypatch):
    """Capture flash messages without requiring a real session."""
    messages = []
    monkeypatch.setattr(
        tk,
        "h",
        SimpleNamespace(
            flash_notice=lambda msg, allow_html=False: messages.append(("notice", msg)),
            flash_error=lambda msg, allow_html=False: messages.append(("error", msg)),
        ),
        raising=False,
    )
    return messages


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


def test_existing_user_update_fullname(plugin, clean_session, mock_services, flash_messages):
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
    assert flash_messages == [
        ("notice", "Your CKAN profile was updated to match Auth0 (full name).")
    ]


def test_existing_user_updates_username_and_email(plugin, clean_session, mock_services, flash_messages):
    """Username and email changes from Auth0 are synced for existing users."""
    user = model.User(
        name="legacyuser",
        email="old-email@example.com",
        fullname="Existing User",
        password="",
    )
    user.plugin_extras = {"oidc_pkce": {"auth0_id": "auth0|999"}}
    model.Session.add(user)
    model.Session.commit()

    userinfo = {
        "sub": "auth0|999",
        "email": "new-email@example.com",
        "name": "Existing User",
        "https://biocommons.org.au/username": "updateduser",
        "access_token": "token-999",
    }

    updated_user = plugin.get_oidc_user(userinfo)

    assert updated_user.id == user.id
    assert updated_user.name == "updateduser"
    assert updated_user.email == "new-email@example.com"
    assert model.Session.query(model.User).count() == 1
    mock_services.token_service.get_user_roles.assert_called_once_with("token-999")
    mock_services.membership_service.apply_role_based_memberships.assert_called_once_with(
        user_name="updateduser",
        roles=["tsi-member"],
        context=mock_services.site_context,
    )
    assert flash_messages == [
        ("notice", "Your CKAN profile was updated to match Auth0 (username and email address).")
    ]


def test_conflicting_username_triggers_error(plugin, clean_session, mock_services):
    """Renaming to a username that already exists is blocked."""
    existing_user = model.User(
        name="takenuser",
        email="taken@example.com",
        fullname="Taken User",
        password="",
    )
    model.Session.add(existing_user)

    auth0_user = model.User(
        name="legacy-name",
        email="legacy@example.com",
        fullname="Legacy User",
        password="",
    )
    auth0_user.plugin_extras = {"oidc_pkce": {"auth0_id": "auth0|conflict"}}
    model.Session.add(auth0_user)
    model.Session.commit()

    userinfo = {
        "sub": "auth0|conflict",
        "email": "legacy@example.com",
        "name": "Legacy User",
        "https://biocommons.org.au/username": "takenuser",
        "access_token": "token-conflict",
    }

    with pytest.raises(tk.ValidationError, match="already taken"):
        plugin.get_oidc_user(userinfo)

    mock_services.token_service.get_user_roles.assert_not_called()
    mock_services.membership_service.apply_role_based_memberships.assert_not_called()


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


def _make_app(plugin):
    app = Flask(__name__)
    app.secret_key = "testing"

    for bp in plugin.get_blueprint():
        app.register_blueprint(bp)

    @app.before_request
    def _ensure_user():
        if not hasattr(g, "user"):
            g.user = None

    return app


def test_admin_login_blueprint_routes(plugin, mock_config, monkeypatch):
    """Admin blueprint redirects to legacy login with a one-time token."""
    app = _make_app(plugin)

    app.add_url_rule("/user/login", endpoint="user.login", view_func=lambda: "login")
    app.add_url_rule("/user/logout", endpoint="user.logout", view_func=lambda: "logout")
    app.add_url_rule("/ckan-admin", endpoint="admin.index", view_func=lambda: "admin")

    monkeypatch.setattr(
        tk,
        "url_for",
        lambda endpoint, **values: url_for(endpoint, **values),
    )

    def _redirect_to(endpoint, **values):
        if endpoint.startswith(("http://", "https://", "/")):
            return redirect(endpoint)
        return redirect(url_for(endpoint, **values))

    monkeypatch.setattr(tk, "redirect_to", _redirect_to)
    messages = []
    monkeypatch.setattr(
        tk,
        "h",
        SimpleNamespace(
            url_is_local=lambda url: url.startswith("/"),
            flash_notice=lambda msg: messages.append(("notice", msg)),
            flash_error=lambda msg: messages.append(("error", msg)),
        ),
        raising=False,
    )
    monkeypatch.setattr(plugin_module, "session", {}, raising=False)

    client = app.test_client()

    response = client.get("/user/admin/login?came_from=/ckan-admin")
    assert response.status_code == 302

    parsed = urlparse(response.headers["Location"])
    assert parsed.path == "/user/login"
    token = parse_qs(parsed.query)["admin_token"][0]
    assert plugin_module.session[plugin_module.SESSION_ADMIN_LOGIN_TOKEN] == token
    assert plugin_module.session[plugin_module.SESSION_ADMIN_LOGIN_TARGET] == "/ckan-admin"

    # Non-local target is ignored
    response = client.get("/user/admin/login?came_from=https://evil.example.com")
    assert response.status_code == 302
    assert plugin_module.SESSION_ADMIN_LOGIN_TARGET not in plugin_module.session


def test_admin_login_logs_out_active_session(plugin, mock_config, monkeypatch):
    """Logged-in users are logged out before seeing the admin login form."""
    app = _make_app(plugin)

    app.add_url_rule("/user/logout", endpoint="user.logout", view_func=lambda: "logout")

    monkeypatch.setattr(
        tk,
        "url_for",
        lambda endpoint, **values: url_for(endpoint, **values),
    )

    def _redirect_to(endpoint, **values):
        return redirect(url_for(endpoint, **values))

    monkeypatch.setattr(tk, "redirect_to", _redirect_to)
    messages = []
    monkeypatch.setattr(
        tk,
        "h",
        SimpleNamespace(
            url_is_local=lambda url: True,
            flash_notice=lambda msg: messages.append(("notice", msg)),
            flash_error=lambda msg: messages.append(("error", msg)),
        ),
        raising=False,
    )
    monkeypatch.setattr(plugin_module, "session", {}, raising=False)

    with app.test_request_context("/user/admin/login"):
        g.user = "sysadmin"
        response = app.view_functions["oidc_pkce_bpa.admin_login"]()

    assert response.status_code == 302
    parsed = urlparse(response.headers["Location"])
    assert parsed.path == "/user/logout"
    assert parse_qs(parsed.query) == {"came_from": ["/user/admin/login"]}
    assert messages == [("notice", "Logging you out before opening the admin login form.")]


def test_force_oidc_login_allows_admin_token(plugin, mock_config, monkeypatch):
    """The force login route defers to the legacy login when an admin token is present."""
    app = _make_app(plugin)

    token = "abc123"
    monkeypatch.setattr(
        plugin_module,
        "session",
        {plugin_module.SESSION_ADMIN_LOGIN_TOKEN: token},
        raising=False,
    )

    sentinel = object()

    def legacy_login():
        return sentinel

    app.add_url_rule("/user/login", endpoint="user.login", view_func=legacy_login)

    def _fail_redirect(*args, **kwargs):
        raise AssertionError("OIDC redirect should not be triggered for admin login")

    monkeypatch.setattr(tk, "redirect_to", _fail_redirect)

    with app.test_request_context(f"/user/login?admin_token={token}"):
        response = app.view_functions["oidc_pkce_bpa_public.force_oidc_login"]()

    assert response is sentinel


def test_admin_login_complete_allows_sysadmin(plugin, mock_config, monkeypatch):
    """Sysadmins completing login are redirected to their requested target."""
    app = _make_app(plugin)

    app.add_url_rule("/ckan-admin", endpoint="admin.index", view_func=lambda: "admin")

    monkeypatch.setattr(
        tk,
        "url_for",
        lambda endpoint, **values: url_for(endpoint, **values),
    )
    def _redirect_to(endpoint, **values):
        if endpoint.startswith(("http://", "https://", "/")):
            return redirect(endpoint)
        return redirect(url_for(endpoint, **values))

    monkeypatch.setattr(tk, "redirect_to", _redirect_to)
    messages = []
    monkeypatch.setattr(
        tk,
        "h",
        SimpleNamespace(
            url_is_local=lambda url: url.startswith("/"),
            flash_notice=lambda msg: messages.append(("notice", msg)),
            flash_error=lambda msg: messages.append(("error", msg)),
        ),
        raising=False,
    )
    monkeypatch.setattr(plugin_module, "session", {}, raising=False)
    monkeypatch.setattr(plugin_module.authz, "is_sysadmin", lambda user: True)

    token = "abc123"
    plugin_module.session[plugin_module.SESSION_ADMIN_LOGIN_TOKEN] = token
    plugin_module.session[plugin_module.SESSION_ADMIN_LOGIN_TARGET] = "/ckan-admin"

    with app.test_request_context(f"/user/admin/logged-in?token={token}"):
        g.user = "sysadmin"
        response = app.view_functions["oidc_pkce_bpa.admin_login_complete"]()

    assert response.status_code == 302
    parsed = urlparse(response.headers["Location"])
    assert parsed.path == "/ckan-admin"
    assert plugin_module.SESSION_ADMIN_LOGIN_TOKEN not in plugin_module.session
    assert plugin_module.SESSION_ADMIN_LOGIN_TARGET not in plugin_module.session
    assert messages == []


def test_admin_login_complete_rejects_non_sysadmin(plugin, mock_config, monkeypatch):
    """Non-sysadmins attempting to use the legacy login are logged out."""
    app = _make_app(plugin)

    app.add_url_rule("/user/logout", endpoint="user.logout", view_func=lambda: "logout")

    monkeypatch.setattr(tk, "url_for", lambda endpoint, **values: url_for(endpoint, **values))
    def _redirect_to(endpoint, **values):
        if endpoint.startswith(("http://", "https://", "/")):
            return redirect(endpoint)
        return redirect(url_for(endpoint, **values))

    monkeypatch.setattr(tk, "redirect_to", _redirect_to)
    messages = []
    monkeypatch.setattr(
        tk,
        "h",
        SimpleNamespace(
            url_is_local=lambda url: url.startswith("/"),
            flash_notice=lambda msg: messages.append(("notice", msg)),
            flash_error=lambda msg: messages.append(("error", msg)),
        ),
        raising=False,
    )
    monkeypatch.setattr(plugin_module, "session", {}, raising=False)
    monkeypatch.setattr(plugin_module.authz, "is_sysadmin", lambda user: False)

    token = "denied"
    plugin_module.session[plugin_module.SESSION_ADMIN_LOGIN_TOKEN] = token

    with app.test_request_context(f"/user/admin/logged-in?token={token}"):
        g.user = "regular"
        response = app.view_functions["oidc_pkce_bpa.admin_login_complete"]()

    assert response.status_code == 302
    parsed = urlparse(response.headers["Location"])
    assert parsed.path == "/user/logout"
    assert messages == [("error", "Only CKAN sysadmins may use the admin login.")]
    assert plugin_module.SESSION_ADMIN_LOGIN_TOKEN not in plugin_module.session
    assert plugin_module.SESSION_ADMIN_LOGIN_TARGET not in plugin_module.session


def test_admin_login_complete_requires_successful_login(plugin, mock_config, monkeypatch):
    """Failed logins send the user back to the admin entry point."""
    app = _make_app(plugin)

    monkeypatch.setattr(tk, "url_for", lambda endpoint, **values: url_for(endpoint, **values))
    def _redirect_to(endpoint, **values):
        if endpoint.startswith(("http://", "https://", "/")):
            return redirect(endpoint)
        return redirect(url_for(endpoint, **values))

    monkeypatch.setattr(tk, "redirect_to", _redirect_to)
    messages = []
    monkeypatch.setattr(
        tk,
        "h",
        SimpleNamespace(
            url_is_local=lambda url: True,
            flash_notice=lambda msg: messages.append(("notice", msg)),
            flash_error=lambda msg: messages.append(("error", msg)),
        ),
        raising=False,
    )
    monkeypatch.setattr(plugin_module, "session", {}, raising=False)

    token = "expired"
    plugin_module.session[plugin_module.SESSION_ADMIN_LOGIN_TOKEN] = token

    with app.test_request_context(f"/user/admin/logged-in?token={token}"):
        g.user = None
        response = app.view_functions["oidc_pkce_bpa.admin_login_complete"]()

    assert response.status_code == 302
    parsed = urlparse(response.headers["Location"])
    assert parsed.path == "/user/admin/login"
    assert messages == [("error", "Login failed. Bad username or password.")]


def test_authenticator_login_redirects_to_oidc(monkeypatch, plugin):
    """Default login route forces users through the OIDC flow."""
    monkeypatch.setattr(plugin_module, "session", {}, raising=False)
    monkeypatch.setattr(
        tk,
        "url_for",
        lambda endpoint, **values: "/user/login" if endpoint == "user.login" else endpoint,
    )
    sentinel = object()

    def fake_redirect(endpoint, **values):
        return sentinel

    monkeypatch.setattr(tk, "redirect_to", fake_redirect)
    monkeypatch.setattr(
        tk,
        "request",
        SimpleNamespace(path="/user/login", args={}),
        raising=False,
    )

    assert plugin.login() is sentinel


def test_authenticator_login_allows_admin_token(monkeypatch, plugin):
    """Admin login tokens bypass the OIDC redirect."""
    token = "abc"
    monkeypatch.setattr(
        tk,
        "url_for",
        lambda endpoint, **values: "/user/login" if endpoint == "user.login" else endpoint,
    )
    monkeypatch.setattr(
        tk,
        "request",
        SimpleNamespace(path="/user/login", args={"admin_token": token}),
        raising=False,
    )
    monkeypatch.setattr(plugin_module, "session", {plugin_module.SESSION_ADMIN_LOGIN_TOKEN: token}, raising=False)

    def _fail_redirect(*args, **kwargs):
        raise AssertionError("redirect should not be called")

    monkeypatch.setattr(tk, "redirect_to", _fail_redirect)

    assert plugin.login() is None


def test_authenticator_login_ignores_other_paths(monkeypatch, plugin):
    """Non login routes are unaffected."""
    monkeypatch.setattr(
        tk,
        "url_for",
        lambda endpoint, **values: "/user/login" if endpoint == "user.login" else endpoint,
    )
    monkeypatch.setattr(
        tk,
        "request",
        SimpleNamespace(path="/dataset", args={}),
        raising=False,
    )
    monkeypatch.setattr(plugin_module, "session", {}, raising=False)

    def _fail_redirect(*args, **kwargs):
        raise AssertionError("redirect should not be called")

    monkeypatch.setattr(tk, "redirect_to", _fail_redirect)

    assert plugin.login() is None


def test_authenticator_logout_clears_tokens(monkeypatch, plugin):
    """Legacy login state is reset on logout."""
    monkeypatch.setattr(
        plugin_module,
        "session",
        {
            plugin_module.SESSION_ADMIN_LOGIN_TOKEN: "token",
            plugin_module.SESSION_ADMIN_LOGIN_TARGET: "/target",
        },
        raising=False,
    )
    plugin.logout()
    assert plugin_module.SESSION_ADMIN_LOGIN_TOKEN not in plugin_module.session
    assert plugin_module.SESSION_ADMIN_LOGIN_TARGET not in plugin_module.session

def test_oidc_login_response_passthrough_user(plugin):
    """When CKAN user sync succeeds we allow the default flow to continue."""
    user = model.User(name="passthrough", password="dummy")
    assert plugin.oidc_login_response(user) is None


def test_oidc_login_response_redirects_to_denied_page(plugin, monkeypatch):
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

    assert result == "/mock/oidc_pkce_bpa_public.login_error"
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
    register_oidc_blueprint(app)

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
    assert response.headers["Location"].endswith("/mock/oidc_pkce_bpa_public.login_error")
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


def test_callback_missing_required_role_shows_authorisation_error(monkeypatch):
    """Missing required Auth0 roles surfaces a friendly authorisation message."""
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
    register_oidc_blueprint(app)

    client = app.test_client()

    with client.session_transaction() as sess:
        sess[plugin_module.SESSION_CAME_FROM] = "original"
        sess[plugin_module.SESSION_STATE] = "state"
        sess[plugin_module.SESSION_VERIFIER] = "verifier"
        sess[plugin_module.SESSION_FORCE_PROMPT] = True

    response = client.get(
        "/user/login/oidc-pkce/callback?error=missing_required_role&error_description="
        "missing_required_role"
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mock/oidc_pkce_bpa_public.login_error")


def test_callback_error_uri_surfaces_help_link(monkeypatch, mock_config):
    """When Auth0 supplies an error_uri we keep the user on CKAN with a link."""
    monkeypatch.setattr(
        tk,
        "redirect_to",
        lambda endpoint: redirect(f"/mock/{endpoint}"),
    )
    captured_render = {}

    def _fake_render(template, extra_vars=None):
        captured_render["template"] = template
        captured_render["extra_vars"] = extra_vars or {}
        return (
            f"Rendered {template}: {captured_render['extra_vars'].get('error_description')} "
            f"@ {captured_render['extra_vars'].get('error_uri')}"
        )

    monkeypatch.setattr(tk, "render", _fake_render, raising=False)

    app = Flask(__name__)
    app.secret_key = "testing"
    register_oidc_blueprint(app)

    client = app.test_client()

    with client.session_transaction() as sess:
        sess[plugin_module.SESSION_CAME_FROM] = "original"
        sess[plugin_module.SESSION_STATE] = "state"
        sess[plugin_module.SESSION_VERIFIER] = "verifier"

    response = client.get(
        "/user/login/oidc-pkce/callback?error=invalid_request&error_description=Need%20approval"
        "&error_uri=https%3A%2F%2Fstatus.example.com%2Ferrors%2Fneed-approval"
    )

    assert response.status_code == 200
    assert captured_render["template"] == "oidc_pkce_bpa/login_error.html"
    assert captured_render["extra_vars"]["error_description"] == "Need approval"
    assert (
        captured_render["extra_vars"]["error_uri"]
        == "https://status.example.com/errors/need-approval"
    )
    body = response.data.decode("utf-8")
    assert "Need approval" in body
    assert "https://status.example.com/errors/need-approval" in body

    with client.session_transaction() as sess:
        assert plugin_module.SESSION_CAME_FROM not in sess
        assert plugin_module.SESSION_STATE not in sess
        assert plugin_module.SESSION_VERIFIER not in sess
        assert plugin_module.SESSION_FORCE_PROMPT not in sess
        assert plugin_module.SESSION_SKIP_OIDC not in sess


def test_denied_redirect_endpoint_is_configurable(plugin, monkeypatch, mock_config):
    """Operators can override the landing page shown after login denial."""
    fake_session = {
        plugin_module.SESSION_CAME_FROM: "/original",
        plugin_module.SESSION_STATE: "state",
    }
    monkeypatch.setattr(plugin_module, "session", fake_session, raising=False)
    mock_config["ckanext.oidc_pkce_bpa.denied_redirect_endpoint"] = "custom.endpoint"

    captured = {}

    def _fake_redirect(endpoint):
        captured["endpoint"] = endpoint
        return f"/mock/{endpoint}"

    monkeypatch.setattr(tk, "redirect_to", _fake_redirect)

    response = SimpleNamespace(status_code=302)
    result = plugin.oidc_login_response(response)

    assert result == "/mock/custom.endpoint"
    assert captured["endpoint"] == "custom.endpoint"
    assert plugin_module.SESSION_CAME_FROM not in fake_session
    assert plugin_module.SESSION_STATE not in fake_session




def test_force_login_triggers_prompt_when_flagged(monkeypatch, mock_config):
    """Force-login produces a direct Auth0 redirect with the expected PKCE params."""
    monkeypatch.setattr(plugin_module.oidc_config, "client_id", lambda: "cid")
    monkeypatch.setattr(plugin_module.oidc_config, "redirect_url", lambda: "https://ckan.example.com/callback")
    monkeypatch.setattr(plugin_module.oidc_config, "scope", lambda: "openid profile email")
    monkeypatch.setattr(plugin_module.oidc_config, "auth_url", lambda: "https://auth.example.com/authorize")
    monkeypatch.setattr(oidc_views.config, "client_id", lambda: "cid")
    monkeypatch.setattr(oidc_views.config, "redirect_url", lambda: "https://ckan.example.com/callback")
    monkeypatch.setattr(oidc_views.config, "scope", lambda: "openid profile email")
    monkeypatch.setattr(oidc_views.config, "auth_url", lambda: "https://auth.example.com/authorize")
    monkeypatch.setattr(plugin_module.oidc_utils, "code_verifier", lambda: "verifier")
    monkeypatch.setattr(plugin_module.oidc_utils, "app_state", lambda: "appstate")
    monkeypatch.setattr(plugin_module.oidc_utils, "code_challenge", lambda _verifier: "challenge")
    monkeypatch.setattr(oidc_views.utils, "code_verifier", lambda: "verifier")
    monkeypatch.setattr(oidc_views.utils, "app_state", lambda: "appstate")
    monkeypatch.setattr(oidc_views.utils, "code_challenge", lambda _verifier: "challenge")

    app = Flask(__name__)
    app.secret_key = "testing"
    register_oidc_blueprint(app)

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


def test_login_route_always_redirects_to_oidc(monkeypatch, mock_config):
    """The login route keeps redirecting to the OIDC flow even if legacy flags exist."""
    monkeypatch.setattr(tk, "redirect_to", lambda endpoint: f"/mock/{endpoint}")
    monkeypatch.setattr(plugin_module.oidc_config, "client_id", lambda: "cid")
    monkeypatch.setattr(plugin_module.oidc_config, "redirect_url", lambda: "https://ckan.example.com/callback")
    monkeypatch.setattr(plugin_module.oidc_config, "scope", lambda: "openid profile email")
    monkeypatch.setattr(plugin_module.oidc_config, "auth_url", lambda: "https://auth.example.com/authorize")
    monkeypatch.setattr(oidc_views.config, "client_id", lambda: "cid")
    monkeypatch.setattr(oidc_views.config, "redirect_url", lambda: "https://ckan.example.com/callback")
    monkeypatch.setattr(oidc_views.config, "scope", lambda: "openid profile email")
    monkeypatch.setattr(oidc_views.config, "auth_url", lambda: "https://auth.example.com/authorize")
    monkeypatch.setattr(plugin_module.oidc_utils, "code_verifier", lambda: "verifier")
    monkeypatch.setattr(plugin_module.oidc_utils, "app_state", lambda: "appstate")
    monkeypatch.setattr(plugin_module.oidc_utils, "code_challenge", lambda _verifier: "challenge")
    monkeypatch.setattr(oidc_views.utils, "code_verifier", lambda: "verifier")
    monkeypatch.setattr(oidc_views.utils, "app_state", lambda: "appstate")
    monkeypatch.setattr(oidc_views.utils, "code_challenge", lambda _verifier: "challenge")

    app = Flask(__name__)
    app.secret_key = "testing"
    register_oidc_blueprint(app)

    client = app.test_client()

    with client.session_transaction() as sess:
        sess[plugin_module.SESSION_SKIP_OIDC] = True

    response = client.get("/user/login")
    assert response.status_code == 302
    location = response.headers["Location"]
    assert location.startswith("https://auth.example.com/authorize")


def test_profile_update_route_redirects_to_portal(monkeypatch, mock_config):
    """Clicking the profile update route sends the user to the portal."""
    messages = []
    monkeypatch.setattr(tk, "h", SimpleNamespace(flash_error=lambda msg: messages.append(msg)), raising=False)
    monkeypatch.setattr(tk, "redirect_to", lambda endpoint, **kwargs: redirect(f"/mock/{endpoint}"), raising=False)
    monkeypatch.setattr(tk, "url_for", lambda endpoint, **kwargs: f"/mock/{endpoint}", raising=False)

    app = Flask(__name__)
    app.secret_key = "testing"
    register_oidc_blueprint(app)

    @app.before_request
    def _fake_user():
        g.user = "alice"
        g.userobj = SimpleNamespace(
            name="alice",
            id="user-1",
            email="alice@example.com",
            display_name="Alice Example",
        )

    client = app.test_client()
    response = client.get("/user/profile/update")

    assert response.status_code == 302
    assert response.headers["Location"] == "https://profiles.example.com/profile"
    assert messages == []


def test_profile_update_route_requires_login(monkeypatch, mock_config):
    """Unauthenticated users are bounced back to the CKAN login screen."""
    messages = []
    monkeypatch.setattr(tk, "h", SimpleNamespace(flash_error=lambda msg: messages.append(msg)), raising=False)
    monkeypatch.setattr(tk, "redirect_to", lambda endpoint, **kwargs: redirect(f"/mock/{endpoint}"), raising=False)
    monkeypatch.setattr(tk, "url_for", lambda endpoint, **kwargs: f"/mock/{endpoint}", raising=False)

    app = Flask(__name__)
    app.secret_key = "testing"
    register_oidc_blueprint(app)

    client = app.test_client()
    response = client.get("/user/profile/update")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mock/user.login")
    assert messages == ["Please log in to update your profile."]


def test_profile_update_route_handles_missing_config(monkeypatch, mock_config):
    """If the portal URL is not configured we keep users on CKAN."""
    mock_config.pop("ckanext.oidc_pkce_bpa.profile_redirect_url", None)

    messages = []
    monkeypatch.setattr(tk, "h", SimpleNamespace(flash_error=lambda msg: messages.append(msg)), raising=False)
    monkeypatch.setattr(tk, "redirect_to", lambda endpoint, **kwargs: redirect(f"/mock/{endpoint}"), raising=False)
    monkeypatch.setattr(tk, "url_for", lambda endpoint, **kwargs: f"/mock/{endpoint}", raising=False)

    app = Flask(__name__)
    app.secret_key = "testing"
    register_oidc_blueprint(app)

    @app.before_request
    def _fake_user():
        g.user = "alice"
        g.userobj = SimpleNamespace(name="alice")

    client = app.test_client()
    response = client.get("/user/profile/update")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mock/user.edit")
    assert messages == ["Profile update portal URL is not configured."]
