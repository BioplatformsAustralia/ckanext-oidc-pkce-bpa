from ckanext.oidc_pkce.plugin import OidcPkcePlugin
from ckan.plugins import SingletonPlugin
import urllib.parse
from flask import request
import ckan.plugins.toolkit as toolkit

class OidcPkceBpaPlugin(OidcPkcePlugin, SingletonPlugin):
    """
    BPA extension plugin extending OIDCPkcePlugin to support Auth0 extra params (e.g., audience, scope).
    """

    def _get_auth0_extra_params(self):
        config = toolkit.config
        param_string = config.get('ckanext.oidc.pkce.auth0_extra_params', '')
        param_pairs = [param.split('=') for param in param_string.split('&') if '=' in param]
        params = {k: v for k, v in param_pairs}
        return params

    def login_redirect(self):
        # Call original method first
        url = super(OidcPkceBpaPlugin, self).login_redirect()

        # Add extra params
        extra_params = self._get_auth0_extra_params()
        if extra_params:
            parsed = urllib.parse.urlparse(url)
            query = dict(urllib.parse.parse_qsl(parsed.query))
            query.update(extra_params)
            new_query = urllib.parse.urlencode(query)
            url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        return url
