import pytest
from ckan import model
import ckan.plugins.toolkit as tk
from unittest.mock import patch

from ckanext.oidc_pkce_bpa.plugin import OidcPkceBpaPlugin
from ckanext.oidc_pkce_bpa import utils


@pytest.fixture
def plugin():
    """Fixture to initialize the plugin."""
    return OidcPkceBpaPlugin()


@pytest.fixture
def clean_session():
    """Fixture to clean up the database session after each test."""
    yield
    model.Session.remove()


@pytest.fixture
def mock_config(monkeypatch):
    """Fixture to set constants used by utils.extract_username and app_metadata parsing."""
    monkeypatch.setattr(utils, "USERNAME_CLAIM", "https://biocommons.org.au/username", raising=False)
    monkeypatch.setattr(utils, "APP_METADATA_CLAIM", "https://biocommons.org.au/app_metadata", raising=False)
    yield


def test_create_new_user(plugin, clean_session, mock_config):
    """Test creating a new user with OIDC user info."""
    userinfo = {
        "sub": "auth0|123",
        "email": "newuser@example.com",
        "name": "New User",
        "https://biocommons.org.au/username": "newuser",
        "access_token": "test-access-token"
    }

    with patch("ckanext.oidc_pkce_bpa.utils.get_user_app_metadata", return_value={}):
        user = plugin.get_oidc_user(userinfo)

    assert user.name == "newuser"
    assert user.email == "newuser@example.com"
    assert user.fullname == "New User"
    assert user.plugin_extras["oidc_pkce"]["auth0_id"] == "auth0|123"


def test_existing_user_backfill_auth0(plugin, clean_session, mock_config):
    """Test updating an existing user with missing Auth0 ID."""
    user = model.User(name="existinguser", email="existing@example.com", fullname="Existing User", password="")
    model.Session.add(user)
    model.Session.commit()

    user.plugin_extras = {}
    model.Session.commit()

    userinfo = {
        "sub": "auth0|456",
        "email": "existing@example.com",
        "name": "Existing User",
        "https://biocommons.org.au/username": "existinguser",
        "access_token": "test-access-token"
    }

    with patch("ckanext.oidc_pkce_bpa.utils.get_user_app_metadata", return_value={}):
        updated_user = plugin.get_oidc_user(userinfo)

    assert updated_user.plugin_extras["oidc_pkce"]["auth0_id"] == "auth0|456"


def test_existing_user_update_fullname(plugin, clean_session, mock_config):
    """Test updating the fullname of an existing user."""
    user = model.User(name="fullnameuser", email="full@example.com", fullname="Old Name", password="")
    user.plugin_extras = {"oidc_pkce": {"auth0_id": "auth0|789"}}
    model.Session.add(user)
    model.Session.commit()

    userinfo = {
        "sub": "auth0|789",
        "email": "full@example.com",
        "name": "New Name",
        "https://biocommons.org.au/username": "fullnameuser",
        "access_token": "test-access-token"
    }

    with patch("ckanext.oidc_pkce_bpa.utils.get_user_app_metadata", return_value={}):
        updated_user = plugin.get_oidc_user(userinfo)

    assert updated_user.fullname == "New Name"


def test_pending_resources_stored(plugin, clean_session, mock_config):
    """Test storing pending resources in the user's plugin extras."""
    userinfo = {
        "sub": "auth0|999",
        "email": "pending@example.com",
        "name": "Pending User",
        "https://biocommons.org.au/username": "pendinguser",
        "access_token": "test-access-token"
    }
    app_metadata = {
        "services": [
            {
                "name": "Bioplatforms Australia Data Portal",
                "id": "bpa",
                "resources": [
                    {
                        "id": "cipps",
                        "name": "ARC for Innovations in Peptide and Protein Science (CIPPS)",
                        "status": "pending",
                        "initial_request_time": "2025-08-02T09:48:54.011361Z",
                        "last_updated": "2025-08-02T09:48:54.011361Z",
                        "updated_by": "system",
                    }
                ],
            }
        ]
    }

    def mock_action(name):
        if name == "organization_show":
            return lambda ctx, data: {"name": data["id"]}
        raise AssertionError(f"Unexpected action requested: {name}")

    with patch("ckan.plugins.toolkit.get_action", side_effect=mock_action), \
         patch("ckanext.oidc_pkce_bpa.plugin.session", {}), \
         patch("ckanext.oidc_pkce_bpa.utils.get_user_app_metadata", return_value=app_metadata), \
         patch("ckanext.oidc_pkce_bpa.utils.sync_org_memberships_from_auth0") as mock_sync:
        user = plugin.get_oidc_user(userinfo)

    org_request = user.plugin_extras["oidc_pkce"]["org_request"]

    assert isinstance(org_request, list)
    assert len(org_request) == 1
    assert org_request[0]["id"] == "cipps"
    assert org_request[0]["status"] == "pending"
    assert org_request[0]["handler"] == "system"
    mock_sync.assert_called_once()


def test_missing_sub_raises(plugin):
    """Test that missing 'sub' in userinfo raises NotAuthorized."""
    userinfo = {
        "email": "missing@example.com",
        "https://biocommons.org.au/username": "someuser"
    }

    with pytest.raises(tk.NotAuthorized, match="sub"):
        plugin.get_oidc_user(userinfo)


def test_missing_username_raises(plugin):
    """Test that missing username in userinfo raises NotAuthorized."""
    userinfo = {
        "sub": "auth0|999",
        "email": "missing@example.com",
        "access_token": "test-access-token"
    }

    with pytest.raises(tk.NotAuthorized, match="Missing 'username' in Auth0 ID token"):
        plugin.get_oidc_user(userinfo)
