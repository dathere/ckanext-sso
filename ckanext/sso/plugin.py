# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import logging
import ckan.plugins as plugins
import ckan.plugins.toolkit as tk

import ckanext.sso.helpers as helpers
from ckanext.sso.views import get_blueprint


log = logging.getLogger(__name__)


class SSOPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.ITemplateHelpers)

    # ITemplateHelpers

    def get_helpers(self):
        return {
            'check_default_login': helpers.check_default_login,
        }

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, 'templates')
        tk.add_public_directory(config_, 'public')
        tk.add_resource('assets', 'sso')

    def get_blueprint(self):
        return get_blueprint()
