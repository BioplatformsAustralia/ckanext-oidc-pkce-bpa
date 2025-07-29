import logging
import re
import ckan.plugins.toolkit as tk
from . import config

from ckan import model

from ckan.plugins import SingletonPlugin, implements

from ckanext.oidc_pkce.interfaces import IOidcPkce

log = logging.getLogger(__name__)

class OidcPkceBpaPlugin(SingletonPlugin):
    implements(IOidcPkce, inherit=True)

    def get_oidc_user(self, userinfo: dict) -> model.User:
        sub = userinfo.get("sub")
        if not sub:
            raise tk.NotAuthorized("'userinfo' missing 'sub' claim during get_oidc_user().")

        # Updated to match the namespaced claim set in the Auth0 action
        username_claim = config.username_claim()
        bpa_username = userinfo.get(username_claim)

        if not bpa_username:
            log.error("AMANDA-DEBUG - USERNAME_CLAIM: %s", username_claim)
            raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")

        user = model.User.get(bpa_username)
        if not user:
            user = model.User(
                name=bpa_username,
                email=userinfo.get("email"),
                fullname=userinfo.get("name", bpa_username),
                password="",  # Not used
            )
            model.Session.add(user)
            model.Session.commit()

            user.plugin_extras = user.plugin_extras or {}
            user.plugin_extras["oidc_pkce"] = {"auth0_id": sub}
            model.Session.commit()
            log.info("Stored Auth0 ID for new user '%s': %s", user.name, sub)

        else:
            extras = user.plugin_extras or {}
            if "oidc_pkce" not in extras:
                extras["oidc_pkce"] = {}

            if "auth0_id" not in extras["oidc_pkce"]:
                extras["oidc_pkce"]["auth0_id"] = sub
                user.plugin_extras = extras
                model.Session.commit()
                log.info("Backfilled Auth0 ID for user '%s': %s", user.name, sub)

            updated_fullname = userinfo.get("name")
            if updated_fullname and user.fullname != updated_fullname:
                log.info("Updating fullname for '%s' to '%s'", user.name, updated_fullname)
                user.fullname = updated_fullname
                model.Session.commit()

        return user
