# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging
from os import access
from wsgiref import headers
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
        authorization_code = tk.request.args.get('code', None)
        if not authorization_code:
            return False

        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None) or tk.request.endpoint != 'static':
            self._identify_user_default(authorization_code)

        # if tk.g.user and not getattr(tk.g, u'userobj', None):
        #     tk.g.userobj = model.User.by_name(tk.g.user)

    def _identify_user_default(self, authorization_code):
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None):
            access_token = self._get_access_token(authorization_code)
            if access_token:
                self.get_user_info(access_token)
        

    def _get_access_token(self, authorization_code):
        credentials = bytes(f"{self.client_id}:{self.client_secret}", 'utf-8')
        authorization = b64encode(credentials).decode()
        print("Authorization: ", authorization)
        headers = {'Authorization': f'Basic {authorization}',
                    'Content-Type': 'application/x-www-form-urlencoded'}
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': authorization_code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_url,
            'scope': 'openid email'
        }
        response = requests.request("POST", self.access_token_url, headers=headers, params=params)
        return response.json()


    def get_user_info(self, access_token):
        token = access_token['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        result = requests.get(self.user_info, headers=headers)
        print('***************************************************')
        print(result.text)
