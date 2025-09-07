import logging

import ckan.plugins.toolkit as tk
from ckan.plugins.toolkit import config as ckan_config, NotAuthorized

log = logging.getLogger(__name__)

USERNAME_CLAIM = ckan_config.get("ckanext.oidc_pkce_bpa.username_claim")


def extract_username(userinfo: dict) -> str:
    username = userinfo.get(USERNAME_CLAIM) or userinfo.get("nickname")
    if not username:
        raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")
    return username

