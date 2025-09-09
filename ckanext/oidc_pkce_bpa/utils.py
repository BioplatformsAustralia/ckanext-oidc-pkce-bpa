import logging

import ckan.plugins.toolkit as tk
from ckan.plugins.toolkit import config as ckan_config, NotAuthorized

log = logging.getLogger(__name__)


def extract_username(userinfo: dict) -> str:
    username_claim = ckan_config.get("ckanext.oidc_pkce_bpa.username_claim")
    username = userinfo.get(username_claim) or userinfo.get("nickname")
    if not username:
        raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")
    return username

def get_redirect_registeration_url() -> str:
    register_redirect_url = ckan_config.get("ckanext.oidc_pkce_bpa.register_redirect_url")
    if not register_redirect_url:
        raise tk.NotAuthorized("redirect_registation_url not set in ckan.ini!")
    return register_redirect_url
