import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from ckanext.oidc_pkce.plugin import OidcPkcePlugin
from ckan.plugins import SingletonPlugin

class OidcPkceBpaPlugin(OidcPkcePlugin, SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "oidc_pkce_bpa")

    