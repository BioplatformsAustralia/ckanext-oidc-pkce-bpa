import pytest
from unittest.mock import patch
from ckanext.oidc_pkce_bpa import utils
import ckan.plugins.toolkit as tk


def test_extract_username_from_claim(monkeypatch):
    # Patch ckan_config.get to return our fake claim key
    monkeypatch.setattr(utils, "ckan_config", {"ckanext.oidc_pkce_bpa.username_claim": "claim_key"})
    userinfo = {"claim_key": "theuser"}
    assert utils.extract_username(userinfo) == "theuser"


def test_extract_username_fallback_and_missing(monkeypatch):
    monkeypatch.setattr(utils, "ckan_config", {"ckanext.oidc_pkce_bpa.username_claim": "claim_key"})
    # Falls back to nickname
    assert utils.extract_username({"nickname": "nick"}) == "nick"

    # Missing both claim and nickname -> raises
    with pytest.raises(tk.NotAuthorized, match="username"):
        utils.extract_username({})


def test_get_redirect_registeration_url_present(monkeypatch):
    monkeypatch.setattr(utils, "ckan_config", {"ckanext.oidc_pkce_bpa.register_redirect_url": "http://example.com/register"})
    assert utils.get_redirect_registeration_url() == "http://example.com/register"


def test_get_redirect_registeration_url_missing(monkeypatch):
    monkeypatch.setattr(utils, "ckan_config", {})
    with pytest.raises(tk.NotAuthorized, match="redirect_registation_url"):
        utils.get_redirect_registeration_url()