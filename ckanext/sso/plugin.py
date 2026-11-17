# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckan.config.declaration import Declaration, Key

import ckanext.sso.helpers as helpers
from ckanext.sso.views import get_blueprint

log = logging.getLogger(__name__)


class SSOPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IConfigDeclaration)

    # ITemplateHelpers

    def get_helpers(self):
        return {
            "check_default_login": helpers.check_default_login,
        }

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_public_directory(config_, "public")
        tk.add_resource("assets", "sso")

    # IConfigDeclaration

    def declare_config_options(self, declaration: Declaration, key: Key):
        
        declaration.annotate("SSO")
        group = key.ckanext.sso
        declaration.declare(
            group.authorization_endpoint,
            "https://sso.example.com/realms/your_realm/protocol/openid-connect/auth",
        )
        declaration.declare(
            group.access_token_url,
            "https://sso.example.com/realms/your_realm/protocol/openid-connect/token",
        )
        declaration.declare(
            group.user_info,
            "https://sso.example.com/realms/your_realm/protocol/openid-connect/userinfo",
        )
        declaration.declare(group.client_id, "sso_client_id")
        declaration.declare(group.client_secret, "sso_client_secret")
        declaration.declare(group.redirect_url, "http://localhost/dashboard")
        declaration.declare(group.response_type, "code")
        declaration.declare(group.scope, "openid profile email")
        declaration.declare(group.role, "member")
        declaration.declare(group.profile_username_field, "preferred_username")
        # LDAP is optional: it is only used when ldap_server is set
        declaration.declare(group.ldap_server, "")
        declaration.declare(group.ldap_base_dn, "")
        declaration.declare(group.ldap_user, "")
        declaration.declare(group.ldap_pass, "")

    def get_blueprint(self):
        return get_blueprint()
