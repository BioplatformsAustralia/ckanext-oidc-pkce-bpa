[![Tests](https://github.com/BioplatformsAustralia/ckanext-oidc-pkce-bpa/workflows/Tests/badge.svg?branch=main)](https://github.com/BioplatformsAustralia/ckanext-oidc-pkce-bpa/actions)

# ckanext-oidc-pkce-bpa

**TODO:** Put a description of your extension here:  What does it do? What features does it have? Consider including some screenshots or embedding a video!


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

None at present

**TODO:** Document any optional config settings here. For example:

	# The minimum number of hours to wait before re-checking a resource
	# (optional, default: 24).
	ckanext.oidc_pkce_bpa.some_setting = some_default_value


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


## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
