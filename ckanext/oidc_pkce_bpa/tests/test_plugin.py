import re
import pytest
from unittest import mock

from ckan import model
import ckan.plugins.toolkit as tk

from ckanext.oidc_pkce_bpa.plugin import OidcPkceBpaPlugin

@pytest.fixture
def plugin():
    return OidcPkceBpaPlugin()

@pytest.fixture
def clean_session():
    yield
    model.Session.remove()

def test_create_new_user(plugin, clean_session):
    userinfo = {
        "sub": "auth0|123",
        "email": "newuser@example.com",
        "name": "New User",
        "https://biocommons.org.au/username": "newuser"
    }

    user = plugin.get_oidc_user(userinfo)

    assert user.name == "newuser"
    assert user.email == "newuser@example.com"
    assert user.fullname == "New User"
    assert user.plugin_extras["oidc_pkce"]["auth0_id"] == "auth0|123"

def test_existing_user_backfill_auth0(plugin, clean_session):
    user = model.User(name="existinguser", email="existing@example.com", fullname="Existing User", password="")
    model.Session.add(user)
    model.Session.commit()

    user.plugin_extras = {}
    model.Session.commit()

    userinfo = {
        "sub": "auth0|456",
        "email": "existing@example.com",
        "name": "Existing User",
        "https://biocommons.org.au/username": "existinguser"
    }

    updated_user = plugin.get_oidc_user(userinfo)
    assert updated_user.plugin_extras["oidc_pkce"]["auth0_id"] == "auth0|456"

def test_existing_user_update_fullname(plugin, clean_session):
    user = model.User(name="fullnameuser", email="full@example.com", fullname="Old Name", password="")
    user.plugin_extras = {"oidc_pkce": {"auth0_id": "auth0|789"}}
    model.Session.add(user)
    model.Session.commit()

    userinfo = {
        "sub": "auth0|789",
        "email": "full@example.com",
        "name": "New Name",
        "https://biocommons.org.au/username": "fullnameuser"
    }

    updated_user = plugin.get_oidc_user(userinfo)
    assert updated_user.fullname == "New Name"

def test_missing_sub_raises(plugin):
    userinfo = {
        "email": "missing@example.com",
        "https://biocommons.org.au/username": "someuser"
    }

    with pytest.raises(tk.NotAuthorized, match="sub"):
        plugin.get_oidc_user(userinfo)

def test_missing_username_raises(plugin):
    userinfo = {
        "sub": "auth0|999",
        "email": "missing@example.com"
    }

    with pytest.raises(tk.NotAuthorized, match="username"):
        plugin.get_oidc_user(userinfo)
