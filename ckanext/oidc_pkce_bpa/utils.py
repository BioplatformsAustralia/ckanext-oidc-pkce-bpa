import json
import time
import jwt
import logging
import requests

from ckan.plugins.toolkit import config as ckan_config, NotAuthorized

from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from jwt.algorithms import RSAAlgorithm  # PyJWT < 2.10
except ImportError:
    RSAAlgorithm = None

try:
    from jwt import PyJWKClient  # PyJWT >= 2.0
except ImportError:
    PyJWKClient = None

import ckan.plugins.toolkit as tk

log = logging.getLogger(__name__)

USERNAME_CLAIM = ckan_config.get("ckanext.oidc_pkce_bpa.username_claim")


def extract_username(userinfo: dict) -> str:
    username = userinfo.get(USERNAME_CLAIM) or userinfo.get("nickname")
    if not username:
        raise tk.NotAuthorized("Missing 'username' in Auth0 ID token")
    return username

