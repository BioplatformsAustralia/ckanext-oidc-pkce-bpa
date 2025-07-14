import logging
from ckan.plugins import SingletonPlugin, implements, interfaces

from ckanext.oidc_pkce.interfaces import IOidcPkce

log = logging.getLogger(__name__)

class OidcPkceBpaPlugin(SingletonPlugin):
    implements(interfaces.IOidcPkce, inherit=True)

