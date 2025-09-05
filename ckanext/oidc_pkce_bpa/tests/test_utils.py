import pytest
from unittest.mock import patch
from ckanext.oidc_pkce_bpa import utils
import ckan.plugins.toolkit as tk

def test_extract_username_from_claim(monkeypatch):
    # USERNAME_CLAIM is now a module-level constant, not a callable config helper
    monkeypatch.setattr(utils, "USERNAME_CLAIM", "claim_key", raising=False)
    userinfo = {"claim_key": "theuser"}
    assert utils.extract_username(userinfo) == "theuser"

def test_extract_username_fallback_and_missing(monkeypatch):
    monkeypatch.setattr(utils, "USERNAME_CLAIM", "claim_key", raising=False)
    assert utils.extract_username({"nickname": "nick"}) == "nick"
    with pytest.raises(tk.NotAuthorized, match="username"):
        utils.extract_username({})
