from setuptools import setup, find_packages

version = '0.1.0'

setup(
    name='ckanext-oidc-pkce-bpa',
    version=version,
    description='Bioplatforms Australia CKAN extension extending ckanext-oidc-pkce for custom Auth0 logic and UI.',
    long_description="""
This extension builds on top of ckanext-oidc-pkce (https://github.com/DataShades/ckanext-oidc-pkce),
adding Bioplatforms Australia-specific behavior such as custom claim parsing, extra routes, and templates.
""",
    classifiers=[],
    keywords='CKAN extension OIDC Auth0 PKCE Bioplatforms',
    author='Bioplatforms Australia',
    author_email='info@bioplatforms.com',
    url='https://github.com/BioplatformsAustralia/ckanext-oidc-pkce-bpa',
    license='MIT',
    packages=find_packages(),
    namespace_packages=['ckanext'],
    include_package_data=True,
    zip_safe=False,
    entry_points="""
        [ckan.plugins]
        oidc_pkce_bpa=ckanext.oidc_pkce_bpa.plugin:OIDCPkceBpaPlugin
    """,
)
