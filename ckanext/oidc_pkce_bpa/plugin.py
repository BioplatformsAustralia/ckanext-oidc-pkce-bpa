import logging
import ckan.plugins.toolkit as tk
from . import config, utils

from ckan import model

from ckan.common import session
from ckan.plugins import SingletonPlugin, implements

from ckanext.oidc_pkce.interfaces import IOidcPkce

log = logging.getLogger(__name__)

class OidcPkceBpaPlugin(SingletonPlugin):
    implements(IOidcPkce, inherit=True)

    def get_oidc_user(self, userinfo: dict) -> model.User:
        sub = userinfo.get("sub")
        if not sub:
            raise tk.NotAuthorized("'userinfo' missing 'sub' claim during get_oidc_user().")

        username = self._extract_username(userinfo)
        user = model.User.get(username)

        if not user:
            user = self._create_new_user(userinfo, username)

        self._ensure_auth0_id(user, sub)
        self._update_fullname_if_needed(user, userinfo)

        self._store_org_metadata(user, userinfo)

        model.Session.add(user)
        model.Session.commit()
        return user

    def _extract_username(self, userinfo: dict) -> str:
        username_claim = config.username_claim()
        username = userinfo.get(username_claim)
        if not username:
            raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")
        return username

    def _create_new_user(self, userinfo: dict, username: str) -> model.User:
        user = model.User(
            name=username,
            email=userinfo.get("email"),
            fullname=userinfo.get("name", username),
            password="",  # Not used
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

    def _store_org_metadata(self, user: model.User, userinfo: dict):
        context = {"user": user.name}
        all_resources = utils.get_org_metadata_from_services(userinfo, context)

        if all_resources:
            user.plugin_extras["oidc_pkce"] = user.plugin_extras.get("oidc_pkce", {})
            user.plugin_extras["oidc_pkce"]["org_requests"] = all_resources
            log.info("Stored %d org access records for user '%s'", len(all_resources), user.name)

            session["ckanext:oidc-pkce-bpa:all_resources_ids"] = all_resources
