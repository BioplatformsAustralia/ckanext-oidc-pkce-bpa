from unittest.mock import patch

from ckanext.oidc_pkce_bpa import config


def test_username_claim_default():
    with patch("ckan.plugins.toolkit.config.get", return_value=config.DEFAULT_USERNAME_CLAIM):
        result = config.username_claim()
        assert result == "https://biocommons.org.au/username"


def test_username_claim_stripped_quotes():
    with patch("ckan.plugins.toolkit.config.get", return_value='"https://biocommons.org.au/username"'):
        result = config.username_claim()
        assert result == "https://biocommons.org.au/username"

    with patch("ckan.plugins.toolkit.config.get", return_value="'https://biocommons.org.au/username'"):
        result = config.username_claim()
        assert result == "https://biocommons.org.au/username"

    with patch("ckan.plugins.toolkit.config.get", return_value="  https://biocommons.org.au/username  "):
        result = config.username_claim()
        assert result == "https://biocommons.org.au/username"


def test_app_metadata_claim_default():
    with patch("ckan.plugins.toolkit.config.get", return_value=config.DEFAULT_APP_METADATA_CLAIM):
        result = config.app_metadata_claim()
        assert result == "https://biocommons.org.au/app_metadata"


def test_app_metadata_claim_stripped_quotes():
    with patch("ckan.plugins.toolkit.config.get", return_value='"https://biocommons.org.au/app_metadata"'):
        result = config.app_metadata_claim()
        assert result == "https://biocommons.org.au/app_metadata"

    with patch("ckan.plugins.toolkit.config.get", return_value="'https://biocommons.org.au/app_metadata'"):
        result = config.app_metadata_claim()
        assert result == "https://biocommons.org.au/app_metadata"

    with patch("ckan.plugins.toolkit.config.get", return_value="  https://biocommons.org.au/app_metadata  "):
        result = config.app_metadata_claim()
        assert result == "https://biocommons.org.au/app_metadata"
