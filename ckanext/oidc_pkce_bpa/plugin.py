from flask import Blueprint, redirect, request
import logging
import uuid
from typing import Optional
from urllib.parse import urlencode

from . import utils

from ckanext.oidc_pkce import config as oidc_config
from ckanext.oidc_pkce import utils as oidc_utils
from ckanext.oidc_pkce import views as oidc_views

from ckan import authz, model
from ckan.common import g, session
from ckan.plugins import SingletonPlugin, implements
from ckan.plugins.interfaces import IBlueprint, IAuthenticator
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce.interfaces import IOidcPkce

SESSION_CAME_FROM = oidc_views.SESSION_CAME_FROM
SESSION_STATE = oidc_views.SESSION_STATE
SESSION_VERIFIER = oidc_views.SESSION_VERIFIER
# Kept for backwards compatibility with existing sessions/config even though the
# extension no longer honours this flag when routing logins.
SESSION_SKIP_OIDC = "ckanext:oidc_pkce_bpa:skip_oidc_login"
SESSION_FORCE_PROMPT = "ckanext:oidc_pkce_bpa:force_prompt_login"
_ORIGINAL_OIDC_CALLBACK = oidc_views.callback
_ORIGINAL_OIDC_LOGIN = None
_ORIGINAL_FORCE_LOGIN = None
SESSION_ADMIN_LOGIN_TOKEN = "ckanext:oidc_pkce_bpa:admin_login_token"
SESSION_ADMIN_LOGIN_TARGET = "ckanext:oidc_pkce_bpa:admin_login_target"


def _oidc_callback_with_email_check(*args, **kwargs):
    """Intercept Auth0 "access_denied" errors to keep users on CKAN."""
    error = tk.request.args.get("error")
    if error == "access_denied":
        error_description = tk.request.args.get("error_description") or ""
        message = error_description or "OIDC login was denied."

        if "email" in error_description.lower() and "verif" in error_description.lower():
            message = (
                "Your email address is not verified. Please check your inbox, confirm your "
                "email address and sign in again."
            )

        log.warning("OIDC callback denied access: %s", error_description or error)
        tk.h.flash_error(message)
        session.pop(SESSION_CAME_FROM, None)
        session.pop(SESSION_STATE, None)
        session.pop(SESSION_VERIFIER, None)
        session[SESSION_FORCE_PROMPT] = True
        return tk.redirect_to("home.index")

    return _ORIGINAL_OIDC_CALLBACK(*args, **kwargs)


def _register_callback_override(state):
    callback_endpoint = "oidc_pkce.callback"
    state.app.view_functions[callback_endpoint] = _oidc_callback_with_email_check

    login_endpoint = "oidc_pkce.login"
    original_login = state.app.view_functions.get(login_endpoint)
    if original_login is None:
        log.warning("oidc_pkce.login endpoint not found; skip override")
    else:
        global _ORIGINAL_OIDC_LOGIN
        _ORIGINAL_OIDC_LOGIN = original_login
        state.app.view_functions[login_endpoint] = _oidc_login_override

    force_login_endpoint = "oidc_pkce.force_oidc_login"
    original = state.app.view_functions.get(force_login_endpoint)
    if original is None:
        log.warning("oidc_pkce.force_oidc_login endpoint not found; skip override")
        return

    global _ORIGINAL_FORCE_LOGIN
    _ORIGINAL_FORCE_LOGIN = original
    state.app.view_functions[force_login_endpoint] = _force_login_override


def _force_login_override(*args, **kwargs):
    # If the previous login attempt was denied, force the Auth0 prompt.
    if session.pop(SESSION_FORCE_PROMPT, False):
        return _build_oidc_login_response(prompt="login")

    # Fall back to the original force-login view when present, otherwise mimic
    # that behaviour.
    if _ORIGINAL_FORCE_LOGIN is not None:
        response = _ORIGINAL_FORCE_LOGIN(*args, **kwargs)
    else:
        response = tk.redirect_to("oidc_pkce.login")

    # The original force-login handler may return a plain string (e.g. when
    # tests stub `tk.redirect_to`). Normalise that into a proper redirect.
    if isinstance(response, str):
        return redirect(response)

    return response


def _oidc_login_override(*args, **kwargs):
    if session.pop(SESSION_FORCE_PROMPT, False):
        return _build_oidc_login_response(prompt="login")

    if _ORIGINAL_OIDC_LOGIN is None:
        return _build_oidc_login_response()

    return _ORIGINAL_OIDC_LOGIN(*args, **kwargs)


def _build_oidc_login_response(prompt: Optional[str] = None):
    verifier = oidc_utils.code_verifier()
    state = oidc_utils.app_state()
    session[SESSION_VERIFIER] = verifier
    session[SESSION_STATE] = state
    session[SESSION_CAME_FROM] = tk.request.args.get("came_from")

    params = {
        "client_id": oidc_config.client_id(),
        "redirect_uri": oidc_config.redirect_url(),
        "scope": oidc_config.scope(),
        "state": state,
        "code_challenge": oidc_utils.code_challenge(verifier),
        "code_challenge_method": "S256",
        "response_type": "code",
        "response_mode": "query",
    }
    if prompt:
        params["prompt"] = prompt

    url = f"{oidc_config.auth_url()}?{urlencode(params)}"
    resp = redirect(url)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


oidc_views.bp.record_once(_register_callback_override)

admin_bp = Blueprint("oidc_pkce_bpa", __name__)

log = logging.getLogger(__name__)


@admin_bp.route("/user/admin/login")
def admin_login():
    """Entry point for sysadmins needing the legacy CKAN login form."""
    if g.user:
        tk.h.flash_notice("Logging you out before opening the admin login form.")
        return tk.redirect_to(
            "user.logout",
            came_from=tk.url_for("oidc_pkce_bpa.admin_login"),
        )

    token = uuid.uuid4().hex
    session[SESSION_ADMIN_LOGIN_TOKEN] = token

    requested_target = request.args.get("came_from")
    if requested_target and tk.h.url_is_local(requested_target):
        session[SESSION_ADMIN_LOGIN_TARGET] = requested_target
    else:
        session.pop(SESSION_ADMIN_LOGIN_TARGET, None)
        if requested_target:
            log.warning("Ignored non-local admin login target: %s", requested_target)

    return tk.redirect_to(
        "user.login",
        admin_token=token,
        came_from=tk.url_for("oidc_pkce_bpa.admin_login_complete", token=token),
    )


@admin_bp.route("/user/admin/logged-in")
def admin_login_complete():
    """Validate admin login attempts and restrict access to sysadmins."""
    token = request.args.get("token")
    stored_token = session.get(SESSION_ADMIN_LOGIN_TOKEN)

    if not stored_token or stored_token != token:
        session.pop(SESSION_ADMIN_LOGIN_TOKEN, None)
        session.pop(SESSION_ADMIN_LOGIN_TARGET, None)
        tk.h.flash_error("The admin login session expired. Please try again.")
        return tk.redirect_to("oidc_pkce_bpa.admin_login")

    if not g.user:
        tk.h.flash_error("Login failed. Bad username or password.")
        return tk.redirect_to("oidc_pkce_bpa.admin_login")

    if not authz.is_sysadmin(g.user):
        session.pop(SESSION_ADMIN_LOGIN_TOKEN, None)
        session.pop(SESSION_ADMIN_LOGIN_TARGET, None)
        tk.h.flash_error("Only CKAN sysadmins may use the admin login.")
        return tk.redirect_to("user.logout")

    redirect_target = session.pop(SESSION_ADMIN_LOGIN_TARGET, None)
    session.pop(SESSION_ADMIN_LOGIN_TOKEN, None)

    if redirect_target and tk.h.url_is_local(redirect_target):
        return tk.redirect_to(redirect_target)

    return tk.redirect_to("admin.index")


class OidcPkceBpaPlugin(SingletonPlugin):
    implements(IOidcPkce, inherit=True)
    implements(IAuthenticator, inherit=True)
    implements(IBlueprint)

    def get_oidc_user(self, userinfo: dict) -> model.User:
        """
        Called post-OIDC login. We resolve/create the CKAN user, then
        (as the site user) grant organization access based on roles in
        the Auth0 access token.
        """
        sub = userinfo.get("sub")
        if not sub:
            raise tk.NotAuthorized("'userinfo' missing 'sub' claim during get_oidc_user().")

        username = utils.extract_username(userinfo)
        user = model.User.get(username) or self._create_new_user(userinfo, username)
        self._ensure_auth0_id(user, sub)
        self._update_fullname_if_needed(user, userinfo)

        access_token = userinfo.get("access_token")
        if not access_token:
            raise tk.ValidationError("No access token available during get_oidc_user()!")

        # Apply roles → membership once, as site user (authorised context).
        # The mapping of Auth0 roles to CKAN organisations is configured via
        # `ckanext.oidc_pkce_bpa.role_org_mapping`.
        token_service = utils.get_token_service()
        try:
            roles = token_service.get_user_roles(access_token)
        except Exception as e:
            log.warning("Failed to read Auth0 roles for '%s': %s", user.name, e)
        else:
            log.debug("Auth0 roles for '%s': %s", user.name, roles)
            try:
                site_ctx = utils.get_site_context()
                membership_service = utils.get_membership_service()
                membership_service.apply_role_based_memberships(
                    user_name=user.name,
                    roles=roles,
                    context=site_ctx,
                )
            except Exception as e:
                log.warning("Role membership apply at login failed for '%s': %s", user.name, e)

        model.Session.add(user)
        model.Session.commit()
        return user

    def oidc_login_response(self, user):
        """Redirect users with login errors back to the CKAN site."""
        if isinstance(user, model.User):
            return None

        status_code = getattr(user, "status_code", None)
        try:
            status_code = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            status_code = None

        if status_code is None or not (300 <= status_code < 400):
            return user

        session.pop(SESSION_CAME_FROM, None)
        session.pop(SESSION_STATE, None)
        return tk.redirect_to("home.index")

    # IAuthenticator

    def login(self):
        login_path = tk.url_for("user.login")
        if tk.request.path != login_path:
            return None

        admin_token = tk.request.args.get("admin_token")
        session_token = session.get(SESSION_ADMIN_LOGIN_TOKEN)
        if admin_token and session_token and admin_token == session_token:
            return None

        return tk.redirect_to("oidc_pkce.force_oidc_login")

    def logout(self):
        session.pop(SESSION_ADMIN_LOGIN_TOKEN, None)
        session.pop(SESSION_ADMIN_LOGIN_TARGET, None)
        return None

    # IBlueprint

    def get_blueprint(self):
        return [admin_bp]

    def _create_new_user(self, userinfo: dict, username: str) -> model.User:
        # Generate a random UUID-based placeholder password that CKAN won't accept
        invalid_password = f"INVALID-{uuid.uuid4()}"
        
        user = model.User(
            name=username,
            email=userinfo.get("email"),
            fullname=userinfo.get("name", username),
            password=invalid_password,
        )
        model.Session.add(user)
        model.Session.commit()
        log.info("Created new user '%s'", username)
        return user

    def _ensure_auth0_id(self, user: model.User, sub: str):
        user.plugin_extras = user.plugin_extras or {}
        extras = user.plugin_extras

        if "oidc_pkce" not in extras:
            extras["oidc_pkce"] = {}

        if "auth0_id" not in extras["oidc_pkce"]:
            extras["oidc_pkce"]["auth0_id"] = sub
            log.info("Backfilled Auth0 ID for user '%s': %s", user.name, sub)

    def _update_fullname_if_needed(self, user: model.User, userinfo: dict):
        updated_fullname = userinfo.get("name")
        if updated_fullname and user.fullname != updated_fullname:
            log.info("Updating fullname for '%s' to '%s'", user.name, updated_fullname)
            user.fullname = updated_fullname

    def get_blueprint(self):
        bp = Blueprint("oidc_pkce_bpa", __name__)

        @bp.route("/user/register")
        def force_oidc_register():
            # hard-redirect to AAI portal user registration page
            return redirect(utils.get_redirect_registeration_url())
    
        @bp.route("/user/login")
        def force_oidc_login():
            # redirect into OIDC login route inside CKAN
            return tk.redirect_to("oidc_pkce.login")
    
        return bp
