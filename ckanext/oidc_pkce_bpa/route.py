import logging
import requests
from flask import Blueprint, request, redirect
from . import plugin

from ckan.plugins.toolkit import config as ckan_config, NotAuthorized
from ckan.common import session

log = logging.getLogger(__name__)
routes = Blueprint("oidc_pkce_bpa", __name__)

AUTH0_DOMAIN = "login.test.biocommons.org.au"
CLIENT_ID = ckan_config.get("ckanext.oidc-pkce.client_id")
CLIENT_SECRET = ckan_config.get("ckanext.oidc-pkce.client_secret")
REDIRECT_URI = "https://login.test.biocommons.org.au/oidc/callback-bpa"

TOKEN_URL = f"https://{AUTH0_DOMAIN}/oauth/token"
USERINFO_URL = f"https://{AUTH0_DOMAIN}/userinfo"

@routes.route("/oidc/callback-bpa")
def handle_oidc_callback():
    code = request.args.get("code")
    if not code:
        raise NotAuthorized("Missing authorization code.")

    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    resp = requests.post(TOKEN_URL, json=data)
    if not resp.ok:
        log.error("Token exchange failed: %s", resp.text)
        raise NotAuthorized("Token exchange failed.")

    tokens = resp.json()
    access_token_raw = tokens.get("access_token")
    if not access_token_raw:
        raise NotAuthorized("Missing access_token from token response")

    # Use access token to fetch userinfo
    headers = {"Authorization": f"Bearer {access_token_raw}"}
    userinfo_resp = requests.get(USERINFO_URL, headers=headers)
    if not userinfo_resp.ok:
        raise NotAuthorized("Failed to fetch userinfo")

    userinfo = userinfo_resp.json()

    # Call your plugin with both
    plugin = plugin.OidcPkceBpaPlugin()
    user = plugin.get_oidc_user(userinfo, access_token_raw)
    session["user"] = user.name

    return redirect("/")
