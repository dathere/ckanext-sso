# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging
from os import access
import requests
import urllib.parse

import secrets

from base64 import b64encode, b64decode

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
import ckan.model as model

import ckanext.sso.helper as helper

log = logging.getLogger(__name__)

class SSOPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IConfigurable)

    def __init__(self, name=None):
        self.sso_helper = helper.SSOHelper()
        self.login_url = tk.config.get('ckan.sso.login_url')
        self.redirect_url = tk.config.get('ckan.sso.redirect_url')
        self.response_type = tk.config.get('ckan.sso.response_type')
        self.scope = tk.config.get('ckan.sso.scope')
        self.client_id = tk.config.get('ckan.sso.client_id')
        self.client_secret = tk.config.get('ckan.sso.client_secret')
        self.identity_provider = tk.config.get('ckan.sso.identity_provider')
        self.access_token_url = tk.config.get('ckan.sso.access_token_url')
        self.user_info = tk.config.get('ckan.sso.user_info')
        self.access_token = None
    

    def configure(self, config):
        required_keys = (
            'ckan.sso.authorization_endpoint',
            'ckan.sso.login_url',
            'ckan.sso.client_id',
            'ckan.sso.client_secret',
            'ckan.sso.redirect_url',
            'ckan.sso.identity_provider',
            'ckan.sso.response_type',
            'ckan.sso.scope'
        )
        for key in required_keys:
            if config.get(key) is None:
                raise RuntimeError('Required configuration option {0} not found.'.format(key))

    def login(self):

        query_string = {'client_id': self.client_id,
                'response_type': self.response_type,
                'scope': self.scope,
                'redirect_uri': self.redirect_url,
                'identity_provider': self.identity_provider
                }
        url = self.login_url + urllib.parse.urlencode(query_string)
        return tk.redirect_to(url)

    def identify(self):
        id_token = tk.request.args.get('id_token', None)
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None) or tk.request.endpoint != 'static':
            self._identify_user_default(id_token)

        # if tk.g.user and not getattr(tk.g, u'userobj', None):
        #     tk.g.userobj = model.User.by_name(tk.g.user)

    def _identify_user_default(self, id_token):
        if tk.request.endpoint != 'static':
            breakpoint()
            id_token = tk.request.args.get('id_token', None)   
            if id_token:
                access_token = tk.request.args.get('access_token', None)
                user = self.get_user_info(access_token)



    def get_user_info(self, access_token):
        breakpoint()
        # credentials = f"{self.client_id}:{self.client_secret}"
        # authorization = b64encode(credentials.encode('utf=8'))

        headers = {'Authorization': f'Bearer {access_token}'}
        result = requests.get(self.user_info, headers=headers)
        print(result)
