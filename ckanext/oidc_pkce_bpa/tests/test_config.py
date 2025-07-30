from unittest import mock

from ckanext.oidc_pkce_bpa.config import (
    username_claim,
    CONFIG_USERNAME_CLAIM,
    DEFAULT_USERNAME_CLAIM,
)


def test_username_claim_from_config():
    with mock.patch("ckan.plugins.toolkit.config.get") as mock_get:
        mock_get.return_value = "custom_claim"
        result = username_claim()
        assert result == "custom_claim"
        mock_get.assert_called_once_with(CONFIG_USERNAME_CLAIM, DEFAULT_USERNAME_CLAIM)


def test_username_claim_uses_default():
    with mock.patch("ckan.plugins.toolkit.config.get") as mock_get:
        mock_get.return_value = DEFAULT_USERNAME_CLAIM
        result = username_claim()
        assert result == DEFAULT_USERNAME_CLAIM
        mock_get.assert_called_once_with(CONFIG_USERNAME_CLAIM, DEFAULT_USERNAME_CLAIM)
