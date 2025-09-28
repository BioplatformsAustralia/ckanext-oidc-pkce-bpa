from flask import Blueprint, redirect
import logging
import uuid

from . import utils

from ckanext.oidc_pkce import views as oidc_views

from ckan import model
from ckan.common import session
from ckan.plugins import SingletonPlugin, implements
from ckan.plugins.interfaces import IBlueprint
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce.interfaces import IOidcPkce

SESSION_CAME_FROM = oidc_views.SESSION_CAME_FROM
SESSION_STATE = oidc_views.SESSION_STATE
SESSION_VERIFIER = oidc_views.SESSION_VERIFIER
# Kept for backwards compatibility with existing sessions/config even though the
# extension no longer honours this flag when routing logins.
SESSION_SKIP_OIDC = "ckanext:oidc_pkce_bpa:skip_oidc_login"
_ORIGINAL_OIDC_CALLBACK = oidc_views.callback
_ORIGINAL_FORCE_LOGIN = None


def _oidc_callback_with_email_check(*args, **kwargs):
    """Intercept Auth0 "access_denied" errors to keep users on the login page."""
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
        return tk.redirect_to("user.login")

    return _ORIGINAL_OIDC_CALLBACK(*args, **kwargs)


def _register_callback_override(state):
    callback_endpoint = "oidc_pkce.callback"
    state.app.view_functions[callback_endpoint] = _oidc_callback_with_email_check

    force_login_endpoint = "oidc_pkce.force_oidc_login"
    original = state.app.view_functions.get(force_login_endpoint)
    if original is None:
        log.warning("oidc_pkce.force_oidc_login endpoint not found; skip override")
        return

    global _ORIGINAL_FORCE_LOGIN
    _ORIGINAL_FORCE_LOGIN = original
    state.app.view_functions[force_login_endpoint] = _force_login_override


def _force_login_override(*args, **kwargs):
    if _ORIGINAL_FORCE_LOGIN is None:
        return tk.redirect_to("oidc_pkce.login")

    return _ORIGINAL_FORCE_LOGIN(*args, **kwargs)


oidc_views.bp.record_once(_register_callback_override)

log = logging.getLogger(__name__)


class OidcPkceBpaPlugin(SingletonPlugin):
    implements(IOidcPkce, inherit=True)
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
        """Redirect users with login errors back to the CKAN login form."""
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
        return tk.redirect_to("user.login")


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
