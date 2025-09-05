import pytest
from ckan import model
import ckan.plugins.toolkit as tk

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
    """Fixture to set constants used by utils.extract_username."""
    monkeypatch.setattr(utils, "USERNAME_CLAIM", "https://biocommons.org.au/username", raising=False)
    # APP_METADATA_CLAIM not needed anymore, so no patch
    yield


def test_create_new_user(plugin, clean_session, mock_config):
    """Test creating a new user with OIDC user info."""
    userinfo = {
        "sub": "auth0|123",
        "email": "newuser@example.com",
        "name": "New User",
        "https://biocommons.org.au/username": "newuser",
    }

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
    }

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
    }

    updated_user = plugin.get_oidc_user(userinfo)

    assert updated_user.fullname == "New Name"


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
    }

    with pytest.raises(tk.NotAuthorized, match="Missing 'username' in Auth0 ID token"):
        plugin.get_oidc_user(userinfo)
