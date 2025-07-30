from __future__ import annotations

import ckan.plugins.toolkit as tk

CONFIG_USERNAME_CLAIM = "ckanext.oidc_pkce_bpa.username_claim"
DEFAULT_USERNAME_CLAIM = "https://biocommons.org.au/username"

def username_claim() -> str:
    """
    Returns the OIDC claim used to extract the username from the ID token/userinfo.

    This reads the value from CKAN config (ckan.ini) using the key defined in CONFIG_USERNAME_CLAIM.
    If not set, it falls back to DEFAULT_USERNAME_CLAIM. Trims quotes or whitespace to avoid misconfigurations.

    Returns:
        str: The claim key used to extract the username (e.g. 'https://biocommons.org.au/username')
    """
    raw = tk.config.get(CONFIG_USERNAME_CLAIM, DEFAULT_USERNAME_CLAIM)
    return raw.strip().strip('"').strip("'")
