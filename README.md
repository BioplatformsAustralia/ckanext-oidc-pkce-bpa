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

        # AAI portal registration/profile/logout URLs
        ckanext.oidc_pkce_bpa.register_redirect_url = 
        ckanext.oidc_pkce_bpa.profile_redirect_url = 
        ckanext.oidc_pkce_bpa.logout_redirect_url = 

        # Support email displayed on the login error page shown to denied users.
        ckanext.oidc_pkce_bpa.support_email = 

        #  Sets the OIDC claim used to extract user roles from Auth0, default is "https://biocommons.org.au/roles"
        ckanext.oidc_pkce_bpa.roles_claim = 

        # Mapping of Auth0 role names to lists of CKAN organisation IDs that should be granted membership when a user authenticates with the mapped role.
        ckanext.oidc_pkce_bpa.role_org_mapping = 



## Bearer token authentication for programmatic API access

In addition to browser-based OIDC login, this extension supports authenticating
CKAN API requests using an Auth0 access token passed as an HTTP Bearer token:

```
Authorization: Bearer <auth0-access-token>
```

This allows users to access protected resources programmatically — for example
via `curl` or `ckanapi` — without a CKAN-issued API key:

```bash
curl -s "https://data.bioplatforms.com/api/3/action/resource_show?id=<id>" \
  -H "Authorization: Bearer <auth0-access-token>"
```

### How it works

The implementation uses CKAN's `IAuthenticator.identify()` hook
([`plugin.py`](./ckanext/oidc_pkce_bpa/plugin.py)), which runs on every
request. When an `Authorization: Bearer <jwt>` header is detected:

1. The JWT is verified against Auth0's JWKS endpoint using RS256, checking audience and issuer
2. The CKAN user is looked up by the stable Auth0 `sub` claim stored in `plugin_extras`, with a fallback to the configured `username_claim`
3. `g.user` and `g.userobj` are set — CKAN's normal `check_access()` authorization then applies per action

This means any downstream extension that builds its request context from
`g.user` / `g.userobj` automatically gains Bearer token support with no
additional changes.

### Example: GA4GH DRS endpoints

`ckanext-drs` is a worked example of this pattern. Its views construct the
CKAN action context directly from `tk.g.user` and `tk.g.userobj`
(see [`ckanext/drs/views.py`](https://github.com/BioplatformsAustralia/ckanext-drs/blob/master/ckanext/drs/views.py)),
meaning DRS object resolution also works with a Bearer token:

```bash
curl -s "https://data.bioplatforms.com/ga4gh/drs/v1/objects/<resource-id>" \
  -H "Authorization: Bearer <auth0-access-token>"
```

### Obtaining an access token

For interactive/scripted use the recommended approach is Auth0's
[Device Authorization Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow),
which opens a browser for the user to authenticate and returns a token to the
calling script. The token must be issued with the audience matching
`ckanext.oidc_pkce_bpa.api_audience` in `ckan.ini`.

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

## Development notes: Logout Redirect Behavior

When an authenticated Auth0-backed user clicks CKAN's logout button, this extension first runs the normal CKAN logout handler so the CKAN session is cleared, then redirects the browser to `ckanext.oidc_pkce_bpa.logout_redirect_url`.

In BPA's AAI setup this should generally point to the logout-start endpoint, for example:

```ini
ckanext.oidc_pkce_bpa.logout_redirect_url = https://dev.login.aai.test.biocommons.org.au/oidc/logout?redirect_uri=https://aaidemo.bioplatforms.com/user/logged_out_redirect
```

## Acknowledgements

This work was supported by Bioplatforms Australia.

Bioplatforms Australia is made possible through investment funding provided
by the Commonwealth Government National Collaborative Research
Infrastructure Strategy (NCRIS).


## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
