import pytest
from unittest.mock import patch, MagicMock
from ckanext.oidc_pkce_bpa import utils

@pytest.fixture
def context():
    return {"user": "testuser"}

@pytest.fixture
def userinfo():
    return {
        "https://biocommons.org.au/app_metadata": {
            "services": [
                {
                    "id": "bpa",
                    "name": "Bioplatforms Australia Data Portal",
                    "resources": [
                        {
                            "id": "cipps",
                            "name": "ARC for Innovations in Peptide and Protein Science (CIPPS)",
                            "status": "approved",
                            "initial_request_time": "2025-08-02T09:48:54.011361Z",
                            "last_updated": "2025-08-02T09:48:54.011361Z",
                            "updated_by": "system"
                        }
                    ]
                }
            ]
        }
    }

@patch("ckan.plugins.toolkit.get_action")
def test_get_org_metadata_from_services(mock_get_action, userinfo, context):
    mock_get_action.return_value = lambda ctx, data: {"name": data["id"]}

    results = utils.get_org_metadata_from_services(userinfo, context)
    assert len(results) == 1
    assert results[0]["id"] == "cipps"
    assert results[0]["status"] == "approved"
    assert results[0]["handler"] == "system"

@patch("ckan.plugins.toolkit.get_action")
def test_sync_org_memberships_from_auth0_adds_member(mock_get_action, context):
    member_list_mock = MagicMock(return_value=[])
    member_create_mock = MagicMock()

    def action(name):
        if name == "member_list":
            return member_list_mock
        elif name == "organization_member_create":
            return member_create_mock
        raise ValueError(name)

    mock_get_action.side_effect = action

    metadata = [{
        "id": "cipps",
        "status": "approved",
        "request_date": "2025-08-02T09:48:54.011361Z",
        "handling_date": "2025-08-02T09:48:54.011361Z",
        "handler": "system",
        "name": "ARC"
    }]

    utils.sync_org_memberships_from_auth0("someuser", metadata, context)
    member_create_mock.assert_called_once_with(context, {
        "id": "cipps",
        "username": "someuser",
        "role": "member"
    })
