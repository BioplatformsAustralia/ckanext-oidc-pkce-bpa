[![Tests](https://github.com/BioplatformsAustralia/ckanext-oidc-pkce-bpa/workflows/Tests/badge.svg?branch=main)](https://github.com/BioplatformsAustralia/ckanext-oidc-pkce-bpa/actions)

# ckanext-oidc-pkce-bpa

This CKAN extension extends the functionality of ckanext-oidc-pkce, a OpenID 
connect with PKCE flow authenticator for CKAN, with customisations
for the integration of the Bioplatforms Australia Data Portal into
the Australian BioCommons Access authentication system.

See: https://www.biocommons.org.au/access


## Requirements
- `pip` (or `pip3` version 24.0+)

Compatibility with core CKAN versions:

| CKAN version    | Compatible?   |
| --------------- | ------------- |
| 2.6 and earlier | not tested    |
| 2.7             | not tested    |
| 2.8             | not tested    |
| 2.9             | yes           |
| 2.10            | yes           |

Suggested values:

* "yes"
* "not tested" - I can't think of a reason why it wouldn't work
* "not yet" - there is an intention to get it working
* "no"


## Installation

To install ckanext-oidc-pkce-bpa:

1. Activate your CKAN virtual environment, for example:

     . /usr/lib/ckan/default/bin/activate

2. Clone the source and install it on the virtualenv

    git clone https://github.com/BioplatformsAustralia/ckanext-oidc-pkce-bpa.git
    cd ckanext-oidc-pkce-bpa
    pip install -e .
	pip install -r requirements.txt

3. Add `oidc-pkce-bpa` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:

     sudo service apache2 reload


## Config settings

        ## OICD PKCE Settings
        # URL of SSO application
        # Could be overriden at runtime with env var CKANEXT_OIDC_PKCE_BASE_URL
        ckanext.oidc_pkce.base_url = 

        # ClientID of SSO application
        # Could be overriden at runtime with env var CKANEXT_OIDC_PKCE_CLIENT_ID
        ckanext.oidc_pkce.client_id = 

        # ClientSecret of SSO application
        # (optional, only need id Client App defines a secret, default: "")
        # Could be overriden at runtime with env var CKANEXT_OIDC_PKCE_CLIENT_SECRET
        ckanext.oidc_pkce.client_secret = 

        # Path to the authorization endpont inside SSO application
        # (optional, default: /oauth2/default/v1/authorize)
        ckanext.oidc_pkce.auth_path = /authorize

        # Path to the token endpont inside SSO application
        # (optional, default: /oauth2/default/v1/token)
        ckanext.oidc_pkce.token_path = /oauth/token

        # Path to the userinfo endpont inside SSO application
        # (optional, default: /oauth2/default/v1/userinfo)
        ckanext.oidc_pkce.userinfo_path = /userinfo

        # Path to the authentication response handler inside CKAN application
        # (optional, default: /user/login/oidc-pkce/callback)
        # ckanext.oidc_pkce.redirect_path = /local/oidc/callback

        # Scope of the authorization token. The plugin expects at least `sub`,
        # `email` and `name` attributes.
        # (optional, default: openid email profile)
        ckanext.oidc_pkce.scope =  openid email profile

        # For newly created CKAN users use the same ID as one from SSO application
        # (optional, default: false)
        ckanext.oidc_pkce.use_same_id = true

        # URL to redirect user in case of failed login attempt.  When empty(default)
        # redirects to `came_from` URL parameter if availabe or to CKAN login page
        # otherwise.
        # (optional, default: )
        ckanext.oidc_pkce.error_redirect = /user/login

        # When connecting to an existing(non-sso) account, override user's password
        # so that it becomes impossible to login using CKAN authentication system.
        # Enable this flag if you want to force SSO-logins for all users that once
        # used SSO-login.
        # (optional, default: false)
        ckanext.oidc_pkce.munge_password = false

        # Auth0 tenant domain for user authentication and Management API requests.
        # This must match the tenant that issues ID tokens and where the target user’s `sub`
        # (subject) identifier comes from. It’s used both for:
        #   - Building the JWKS URL when decoding/verifying JWTs.
        #   - Making Management API calls (if access token is not available).
        #
        # Example: login.test.biocommons.org.au
        ##
        ckanext.oidc_pkce_bpa.auth0_domain = 

        # Auth0 API Audience for JWT verification or Management API calls.
        #
        # - If you’re verifying **user access tokens** issued by Auth0, this should be the
        #   audience value configured in your Auth0 API settings for your CKAN application.
        #
        # - If you’re using the **Auth0 Management API** with client credentials, this should
        #   be set to the Management API audience:
        #       https://<your-auth0-domain>/api/v2/
        #
        # NOTE: The value must exactly match what Auth0 expects; a mismatch will cause
        # JWT validation failures or Management API 401 errors.
        #
        # Example for Management API:
        #   https://dev-bc.au.auth0.com/api/v2/
        ckanext.oidc_pkce_bpa.api_audience = 

        # The JWT claim to use as the CKAN username when authenticating via OIDC (Auth0).
        # This should match the custom namespaced claim added by the Auth0 action.
        ckanext.oidc_pkce_bpa.username_claim = 

        # AAI portal login/registration/profile URLs
        ckanext.oidc_pkce_bpa.login_redirect_url = 
        ckanext.oidc_pkce_bpa.register_redirect_url = 
        ckanext.oidc_pkce_bpa.profile_redirect_url = 

        # Support email displayed on the login error page shown to denied users.
        ckanext.oidc_pkce_bpa.support_email = 

        #  Sets the OIDC claim used to extract user roles from Auth0, default is "https://biocommons.org.au/roles"
        ckanext.oidc_pkce_bpa.roles_claim = 

        # Mapping of Auth0 role names to lists of CKAN organisation IDs that should be granted membership when a user authenticates with the mapped role.
        ckanext.oidc_pkce_bpa.role_org_mapping = 



## Developer installation

To install ckanext-oidc-pkce-bpa for development, install, activate your CKAN virtualenv and
do:

```bash
    python3 -m venv venv
    source venv/bin/activate
    (venv) pip install -r dev-requirements.txt
```

## Tests

To run the tests, do:
```bash
    pytest --ckan-ini=test.ini --cov=ckanext.oidc_pkce_bpa --disable-warnings ckanext/oidc_pkce_bpa
```

## Releasing a new version of ckanext-oidc-pkce-bpa

If ckanext-oidc-pkce-bpa should be available on PyPI you can follow these steps to publish a new version:

1. Update the version number in the `setup.py` file. See [PEP 440](http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers) for how to choose version numbers.

2. Make sure you have the latest version of necessary packages:

    pip install --upgrade setuptools wheel twine

3. Create a source and binary distributions of the new version:

       python setup.py sdist bdist_wheel && twine check dist/*

   Fix any errors you get.

4. Upload the source distribution to PyPI:

       twine upload dist/*

5. Commit any outstanding changes:

       git commit -a
       git push

6. Tag the new release of the project on GitHub with the version number from
   the `setup.py` file. For example if the version number in `setup.py` is
   0.0.1 then do:

       git tag 0.0.1
       git push --tags

## Development notes: Redirect Behavior on Auth0 Callback Errors

When the Auth0 OIDC callback denies access (for example, if a user cancels login or an authorization error occurs), this extension intentionally redirects the user to a configurable CKAN endpoint that does **not** re-trigger the login loop (defaults to `oidc_pkce_bpa_public.login_error`) ([see source](./ckanext/oidc_pkce_bpa/plugin.py)):

```python
session.pop(SESSION_STATE, None)
session.pop(SESSION_VERIFIER, None)
session[SESSION_FORCE_PROMPT] = True
return tk.redirect_to(
    tk.config.get(
        "ckanext.oidc_pkce_bpa.denied_redirect_endpoint",
        "oidc_pkce_bpa_public.login_error",
    )
)
```

#### Rationale

The `/user/login` route in this extension is overridden to immediately start the OIDC login flow.
If a user is redirected there after an Auth0 error, it would immediately trigger another OIDC login attempt, creating an infinite redirect loop and preventing the user from ever seeing the flashed error message.

Redirecting to a CKAN page provides a stable landing point, allowing the user to:
- See the flashed error banner
- Recover gracefully
- Decide whether to retry login or navigate elsewhere.

The default `oidc_pkce_bpa_public.login_error` view lives at `/user/login/error`, contains BPA-specific support messaging, and **requires** the `ckanext.oidc_pkce_bpa.support_email` setting (for example `aai-dev@biocommons.org.au`). Override `ckanext.oidc_pkce_bpa.denied_redirect_endpoint` if you need to render a different page, but keep it pointed at a CKAN route that does **not** re-trigger the OIDC login flow.


## Acknowledgements

This work was supported by Bioplatforms Australia.

Bioplatforms Australia is made possible through investment funding provided
by the Commonwealth Government National Collaborative Research
Infrastructure Strategy (NCRIS).


## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
