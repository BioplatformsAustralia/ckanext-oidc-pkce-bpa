import pytest
from unittest.mock import patch
from ckanext.oidc_pkce_bpa import utils
import ckan.plugins.toolkit as tk

def test_extract_username_from_claim(monkeypatch):
    monkeypatch.setattr(utils.config, "username_claim", lambda: "claim_key")
    userinfo = {"claim_key": "theuser"}
    assert utils.extract_username(userinfo) == "theuser"

def test_extract_username_fallback_and_missing(monkeypatch):
    monkeypatch.setattr(utils.config, "username_claim", lambda: "claim_key")
    assert utils.extract_username({"nickname": "nick"}) == "nick"
    with pytest.raises(tk.NotAuthorized, match="username"):
        utils.extract_username({})

@pytest.mark.parametrize(
    "inp,expected",
    [
        ("2025-08-02T09:48:54.011361Z", "2025-08-02"),
        ("2025-08-02", "2025-08-02"),
        ("not-a-date", "not-a-date"),
    ],
)
def test_format_date(inp, expected):
    assert utils.format_date(inp) == expected

@patch("ckanext.oidc_pkce_bpa.utils.requests.get")
def test_get_jwks(mock_get):
    mock_get.return_value.json.return_value = {"keys": []}
    mock_get.return_value.raise_for_status.return_value = None
    result = utils.get_jwks()
    assert result == {"keys": []}
    mock_get.assert_called_once()

@pytest.mark.skipif(utils.RSAAlgorithm is None, reason="RSAAlgorithm not available in this PyJWT")
@patch("ckanext.oidc_pkce_bpa.utils.get_jwks")
@patch("ckanext.oidc_pkce_bpa.utils.jwt.get_unverified_header")
def test_get_signing_key_found(mock_get_header, mock_get_jwks, monkeypatch):
    mock_get_header.return_value = {"kid": "123"}
    mock_get_jwks.return_value = {"keys": [{"kid": "123"}]}
    # Patch RSAAlgorithm.from_jwk only if RSAAlgorithm exists
    monkeypatch.setattr(utils.RSAAlgorithm, "from_jwk", staticmethod(lambda s: "legacy-key"))
    assert utils.get_signing_key("token") == "legacy-key"

@pytest.mark.skipif(utils.PyJWKClient is None, reason="PyJWKClient not available in this PyJWT")
def test_get_signing_key_pyjwkclient(monkeypatch):
    # Force the new path
    monkeypatch.setattr(utils, "RSAAlgorithm", None, raising=False)

    class MockJWKClient:
        def __init__(self, url): pass
        def get_signing_key_from_jwt(self, token):
            class K:
                key = "pyjwk-key"
            return K()

    monkeypatch.setattr(utils, "PyJWKClient", MockJWKClient, raising=False)
    assert utils.get_signing_key("token") == "pyjwk-key"

@patch("ckanext.oidc_pkce_bpa.utils.get_signing_key")
@patch("ckanext.oidc_pkce_bpa.utils.jwt.decode")
def test_decode_access_token_valid(mock_decode, mock_get_key):
    mock_decode.side_effect = [
        {"header": "no-verify"},  # first decode without verification
        {"decoded": True}         # second decode verified
    ]
    mock_get_key.return_value = "key"
    result = utils.decode_access_token("token")
    assert result == {"decoded": True}

def test_decode_access_token_already_dict():
    assert utils.decode_access_token({"some": "dict"}) == {"some": "dict"}

@patch("ckanext.oidc_pkce_bpa.utils.requests.post")
@patch("ckanext.oidc_pkce_bpa.utils._now", return_value=100)
def test_get_management_token_new(mock_now, mock_post, monkeypatch):
    monkeypatch.setattr(utils, "MGMT_CLIENT_ID", "id")
    monkeypatch.setattr(utils, "MGMT_CLIENT_SECRET", "sec")
    monkeypatch.setattr(utils, "API_AUDIENCE", "aud")
    mock_post.return_value.json.return_value = {"access_token": "tok"}
    mock_post.return_value.raise_for_status.return_value = None
    tok = utils.get_management_token()
    assert tok == "tok"

@patch("ckanext.oidc_pkce_bpa.utils.get_management_token", return_value="tok")
@patch("ckanext.oidc_pkce_bpa.utils.requests.get")
def test_get_user_app_metadata_success(mock_get, mock_token):
    mock_get.return_value.json.return_value = {"app_metadata": {"key": "val"}}
    mock_get.return_value.raise_for_status.return_value = None
    assert utils.get_user_app_metadata("sub") == {"key": "val"}
