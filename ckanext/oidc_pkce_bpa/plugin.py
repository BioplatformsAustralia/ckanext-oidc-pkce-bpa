import logging
import ckan.plugins.toolkit as tk
from . import utils

from ckan import model

from ckan.common import session
from ckan.plugins import SingletonPlugin, implements

from ckanext.oidc_pkce.interfaces import IOidcPkce

log = logging.getLogger(__name__)


class OidcPkceBpaPlugin(SingletonPlugin):
    implements(IOidcPkce, inherit=True)

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

        # --- Fetch app_metadata via Auth0 Management API (no access token needed) ---
        app_metadata = utils.get_user_app_metadata(sub)

        if app_metadata:
            self._store_org_metadata_and_sync(user, app_metadata)
        else:
            log.info("No app_metadata for sub '%s' from Auth0 Management API.", sub)

        model.Session.add(user)
        model.Session.commit()
        return user

    def _create_new_user(self, userinfo: dict, username: str) -> model.User:
        user = model.User(
            name=username,
            email=userinfo.get("email"),
            fullname=userinfo.get("name", username),
            password="",  # Not used (OIDC-managed)
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

    def _store_org_metadata_and_sync(self, user: model.User, claims_or_app_metadata: dict):
        """
        Accepts raw app_metadata and:
          - stores for UI (My Memberships) in session
          - optionally mirrors pending into ckanext-ytp-request
        """
        context = {"user": user.name}

        org_metadata = utils.get_org_metadata_from_services(claims_or_app_metadata, context)
        if not org_metadata:
            return

        # Persist on the user for audit/inspection
        user.plugin_extras["oidc_pkce"] = user.plugin_extras.get("oidc_pkce", {})
        user.plugin_extras["oidc_pkce"]["org_request"] = org_metadata

        # Surface to the UI via session for the My Memberships page
        session["ckanext:oidc-pkce-bpa:org_metadata"] = org_metadata
        log.info("Stored %d org resource records for user '%s'", len(org_metadata), user.name)

        # Optionally create pending requests in ytp-request if not present
        utils.sync_org_memberships_from_auth0(user.name, org_metadata, context)
