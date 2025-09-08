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
    redirect_registeration_url = ckan_config.get("ckanext.oidc_pkce_bpa.redirect_registration_url")
    if not redirect_registeration_url:
        raise tk.NotAuthorized("Missing redirect registation url set in ckan.ini!")
    return redirect_registeration_url