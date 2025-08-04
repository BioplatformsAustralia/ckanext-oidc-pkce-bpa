from __future__ import annotations

import ckan.plugins.toolkit as tk

CONFIG_USERNAME_CLAIM = "ckanext.oidc_pkce_bpa.username_claim"
DEFAULT_USERNAME_CLAIM = "https://biocommons.org.au/username"

CONFIG_APP_METADATA_CLAIM = "ckanext.oidc_pkce_bpa.app_metadata_claim"
DEFAULT_APP_METADATA_CLAIM = "https://biocommons.org.au/app_metadata"

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

def app_metadata_claim() -> str:
    """
    Returns the OIDC claim used to extract app_metadata from the ID token/userinfo.

    Reads from CKAN config key 'ckanext.oidc_pkce_bpa.app_metadata_claim'. Falls back to default.
    Trims quotes and whitespace for safety.

    Returns:
        str: The claim key used to extract app_metadata (e.g. 'https://biocommons.org.au/app_metadata')
    """
    raw = tk.config.get(CONFIG_APP_METADATA_CLAIM, DEFAULT_APP_METADATA_CLAIM)
    return raw.strip().strip('"').strip("'")
