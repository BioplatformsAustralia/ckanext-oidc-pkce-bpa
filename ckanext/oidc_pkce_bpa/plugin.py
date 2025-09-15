from flask import Blueprint, redirect
import logging
import uuid

from . import utils

from ckan import model
from ckan.common import session
from ckan.plugins import SingletonPlugin, implements
from ckan.plugins.interfaces import IBlueprint
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce.interfaces import IOidcPkce

log = logging.getLogger(__name__)


class OidcPkceBpaPlugin(SingletonPlugin):
    implements(IOidcPkce, inherit=True)
    # implements(IBlueprint)

    def get_oidc_user(self, userinfo: dict) -> model.User:
        """
        Upstream calls this with only `userinfo`. We fetch app_metadata via
        the Auth0 Management API using the user's `sub` and then normalise +
        stash it for UI (and optionally sync into ytp-request).
        """
        sub = userinfo.get("sub")
        if not sub:
            raise tk.NotAuthorized("'userinfo' missing 'sub' claim during get_oidc_user().")

        # Resolve or create the CKAN user
        username = utils.extract_username(userinfo)
        user = model.User.get(username)
        if not user:
            user = self._create_new_user(userinfo, username)

        # Keep basic identity fields aligned
        self._ensure_auth0_id(user, sub)
        self._update_fullname_if_needed(user, userinfo)

        model.Session.add(user)
        model.Session.commit()
        return user

    def apply_role_memberships(self, *, user: model.User, access_token: str):
        """
        Decode roles from the access token and apply role-triggered membership actions.
        Currently: if role == 'biocommons/group/tsi', create a pending request for
        the 'aai-threatened-species-initiative-embargo' organization (idempotent).
        """
        try:
            roles = utils.get_user_roles(access_token)
        except Exception as e:
            log.warning("Could not read roles from access token for user '%s': %s", user.name, e)
            return

        context = {"model": model, "user": user.name}
        utils.apply_role_based_memberships(user_name=user.name, roles=roles, context=context)


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
        bp = Blueprint("oidc_pkce_bpa_routes", __name__)

        @bp.route("/user/register")
        def force_oidc_register():
            # hard-redirect to AAI portal user registration page
            return redirect(utils.get_redirect_registeration_url())

        @bp.route("/user/login")
        def force_oidc_login():
            # redirect into OIDC login route inside CKAN
            return tk.redirect_to("oidc_pkce.login")

        return bp
