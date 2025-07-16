"""
Tests for plugin.py.

Tests are written using the pytest library (https://docs.pytest.org), and you
should read the testing guidelines in the CKAN docs:
https://docs.ckan.org/en/2.9/contributing/testing.html

To write tests for your extension you should install the pytest-ckan package:

    pip install pytest-ckan

This will allow you to use CKAN specific fixtures on your tests.

For instance, if your test involves database access you can use `clean_db` to
reset the database:

    import pytest

    from ckan.tests import factories

    @pytest.mark.usefixtures("clean_db")
    def test_some_action():

        dataset = factories.Dataset()

        # ...

For functional tests that involve requests to the application, you can use the
`app` fixture:

    from ckan.plugins import toolkit

    def test_some_endpoint(app):

        url = toolkit.url_for('myblueprint.some_endpoint')

        response = app.get(url)

        assert response.status_code == 200


To temporary patch the CKAN configuration for the duration of a test you can use:

    import pytest

    @pytest.mark.ckan_config("ckanext.myext.some_key", "some_value")
    def test_some_action():
        pass
"""
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
        "username": "newuser"
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
        "username": "existinguser"
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
        "username": "fullnameuser"
    }

    updated_user = plugin.get_oidc_user(userinfo)
    assert updated_user.fullname == "New Name"

def test_missing_sub_raises(plugin):
    userinfo = {
        "email": "missing@example.com",
        "username": "someuser"
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

def test_invalid_username_raises(plugin):
    userinfo = {
        "sub": "auth0|999",
        "email": "badformat@example.com",
        "username": "Invalid!User"
    }

    with pytest.raises(tk.ValidationError, match="Invalid BPA username format"):
        plugin.get_oidc_user(userinfo)
