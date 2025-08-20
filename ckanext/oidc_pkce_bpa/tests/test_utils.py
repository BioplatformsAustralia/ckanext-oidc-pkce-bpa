import pytest
from unittest.mock import patch, MagicMock
from ckan.plugins.toolkit import NotAuthorized, ValidationError
from ckanext.oidc_pkce_bpa.utils import (
    extract_username,
    format_date,
    get_jwks,
    get_signing_key,
    decode_access_token,
    _services_to_org_entries,
    get_org_metadata_from_services,
    sync_org_memberships_from_auth0,
    get_user_app_metadata,
)

# Mock configuration values
USERNAME_CLAIM = "https://biocommons.org.au/username"
APP_METADATA_CLAIM = "https://biocommons.org.au/app_metadata"


@pytest.fixture
def mock_config():
    """Fixture to mock configuration values."""
    with patch("ckanext.oidc_pkce_bpa.utils.ckan_config.get") as mock_config:
        mock_config.side_effect = lambda key: {
            "ckanext.oidc_pkce_bpa.username_claim": USERNAME_CLAIM,
            "ckanext.oidc_pkce_bpa.app_metadata_claim": APP_METADATA_CLAIM,
        }.get(key)
        yield mock_config


def test_extract_username(mock_config):
    """Test extracting username from userinfo."""
    userinfo = {USERNAME_CLAIM: "testuser"}
    assert extract_username(userinfo) == "testuser"

    userinfo = {"nickname": "nicknameuser"}
    assert extract_username(userinfo) == "nicknameuser"

    userinfo = {}
    with pytest.raises(NotAuthorized, match="Missing 'username' in Auth0 ID token"):
        extract_username(userinfo)


def test_format_date():
    """Test formatting ISO 8601 date strings."""
    assert format_date("2025-08-20T12:34:56Z") == "2025-08-20"
    assert format_date("invalid-date") == "invalid-date"


@patch("ckanext.oidc_pkce_bpa.utils.requests.get")
def test_get_jwks(mock_get):
    """Test fetching JWKS."""
    mock_get.return_value = MagicMock(status_code=200, json=lambda: {"keys": []})
    jwks = get_jwks()
    assert jwks == {"keys": []}
    mock_get.assert_called_once()


@patch("ckanext.oidc_pkce_bpa.utils.jwt.get_unverified_header")
@patch("ckanext.oidc_pkce_bpa.utils.get_jwks")
def test_get_signing_key_rsa(mock_get_jwks, mock_get_unverified_header):
    """Test getting signing key using RSAAlgorithm."""
    mock_get_unverified_header.return_value = {"kid": "test-kid"}
    mock_get_jwks.return_value = {"keys": [{"kid": "test-kid", "key": "test-key"}]}

    with patch("ckanext.oidc_pkce_bpa.utils.RSAAlgorithm.from_jwk", return_value="rsa-key"):
        key = get_signing_key("test-token")
        assert key == "rsa-key"


@patch("ckanext.oidc_pkce_bpa.utils.jwt.decode")
@patch("ckanext.oidc_pkce_bpa.utils.get_signing_key")
def test_decode_access_token(mock_get_signing_key, mock_decode):
    """Test decoding and verifying a JWT token."""
    mock_get_signing_key.return_value = "test-key"
    mock_decode.return_value = {"sub": "123"}

    token = "test-token"
    decoded = decode_access_token(token)
    assert decoded == {"sub": "123"}


def test_services_to_org_entries():
    """Test converting services to org entries."""
    services = [
        {
            "resources": [
                {
                    "id": "org1",
                    "name": "Organization 1",
                    "status": "pending",
                    "initial_request_time": "2025-08-20T12:34:56Z",
                    "last_updated": "2025-08-21T12:34:56Z",
                    "updated_by": "admin",
                }
            ]
        }
    ]
    context = {}

    with patch("ckanext.oidc_pkce_bpa.utils.tk.get_action") as mock_action:
        mock_action.return_value = lambda ctx, data: {"id": data["id"]}
        org_entries = _services_to_org_entries(services, context)

    assert len(org_entries) == 1
    assert org_entries[0]["id"] == "org1"
    assert org_entries[0]["status"] == "pending"
    assert org_entries[0]["request_date"] == "2025-08-20"
    assert org_entries[0]["handling_date"] == "2025-08-21"


def test_get_org_metadata_from_services(mock_config):
    """Test extracting org metadata from services."""
    app_metadata = {
        APP_METADATA_CLAIM: {
            "services": [
                {
                    "resources": [
                        {
                            "id": "org1",
                            "name": "Organization 1",
                            "status": "approved",
                        }
                    ]
                }
            ]
        }
    }
    context = {}

    with patch("ckanext.oidc_pkce_bpa.utils._services_to_org_entries", return_value=[{"id": "org1"}]):
        org_metadata = get_org_metadata_from_services(app_metadata, context)

    assert len(org_metadata) == 1
    assert org_metadata[0]["id"] == "org1"


def test_sync_org_memberships_from_auth0():
    """Test syncing org memberships from Auth0."""
    user_name = "testuser"
    org_metadata = [{"id": "org1", "status": "approved"}]
    context = {}

    with patch("ckanext.oidc_pkce_bpa.utils.tk.get_action") as mock_action:
        mock_action.side_effect = lambda name: {
            "organization_show": lambda ctx, data: {"id": data["id"]},
            "member_requests_list": lambda ctx, data: [],
            "member_request_create": lambda ctx, data: data,
        }[name]

        sync_org_memberships_from_auth0(user_name, org_metadata, context)


def test_get_user_app_metadata(mock_config):
    """Test extracting app metadata from access token."""
    access_token = {"https://biocommons.org.au/app_metadata": {"key": "value"}}
    app_metadata = get_user_app_metadata(access_token)
    assert app_metadata == {"key": "value"}

    with pytest.raises(ValidationError, match="Access token is required but missing"):
        get_user_app_metadata(None)
