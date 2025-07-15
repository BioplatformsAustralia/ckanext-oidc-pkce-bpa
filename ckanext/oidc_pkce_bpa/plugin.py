import logging
from ckan.plugins import SingletonPlugin, implements

from ckanext.oidc_pkce.interfaces import IOidcPkce

log = logging.getLogger(__name__)

class OidcPkceBpaPlugin(SingletonPlugin):
    implements(IOidcPkce, inherit=True)

