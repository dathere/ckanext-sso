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
from ckan.views.user import set_repoze_user

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
        self.id_token = None
        self.refresh_token = None
    

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
        return self._ckan_login() if self._check_cookies() else self._cognito_login()

    def _check_cookies(self):
        self.access_token = tk.request.cookies.get('access_token')
        self.id_token = tk.request.cookies.get('id_token')
        self.refresh_token = tk.request.cookies.get('refresh_token')
        return bool(self.id_token or self.access_token or self.refresh_token)

    def _ckan_login(self):
        
        user = self.get_user_info(self.access_token)
        self._authenticate_user(user)
    
    def _cognito_login(self):
        query_string = {'client_id': self.client_id,
                'response_type': self.response_type,
                'scope': self.scope,
                'redirect_uri': self.redirect_url,
                'identity_provider': self.identity_provider
                }
        url = self.login_url + urllib.parse.urlencode(query_string)
        return tk.redirect_to(url)


    def logout(self):
        pass

    def identify(self):
        authorization_code = tk.request.args.get('code', None)
        if not authorization_code:
            return False

        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None) or tk.request.endpoint != 'static':
            user = self._identify_user_default(authorization_code)
            if user:
                self._authenticate_user(user)
        return None

    def _identify_user(self, access_token):
        user_info = self.get_user_info(access_token)
        if user_info:
            user = self._get_or_create_user(user_info)
            if user:
                return user
        
    def _identify_user_default(self, authorization_code):
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None):
            access_token = self._get_access_token(authorization_code)
            if access_token:
                return self._identify_user(access_token)
            else:
                log.error('No access token found')
                tk.redirect_to(self.redirect_url)
        

    def _get_access_token(self, authorization_code):
        credentials = bytes(f"{self.client_id}:{self.client_secret}", 'utf-8')
        authorization = b64encode(credentials).decode()
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
        try:
            response = requests.request("POST", self.access_token_url, headers=headers, params=params)
        except tk.ValidationError:
            return False
        return response.json()


    def get_user_info(self, access_token):
        token = access_token['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        result = requests.get(self.user_info, headers=headers)
        return result.json()
    

    def _get_or_create_user(self, user_info):
        context = self._prepare_context()
        try:    
            user = tk.get_action('user_show')(context, {'id': user_info['custom:userid']})
            log.debug(f"User found {user.get('name')}")
            return user
        except tk.ObjectNotFound:
            log.debug("User not found, attempt to create it")
            user_dict = {
                'name': user_info['username'].split('@')[0],
                'email': user_info['email'],
                'full_name': user_info['name'],
                'password': secrets.token_urlsafe(16),
                'plugin_extras': {
                    'sso': user_info['sub']                }
            }
            user = tk.get_action('user_create')(context, user_dict) 
            return user

    def _prepare_context(self):
        site_user = tk.get_action('get_site_user')({'model': model, 'ignore_auth': True}, {})
        return {'model': model, 'session': model.Session, 'ignore_auth': True, 'user': site_user['name']}

    def _authenticate_user(self, user):
        # log the user in programmatically
        tk.g.user = user.get('name')
        tk.g.userobj = user
        response = tk.redirect_to(self.redirect_url)
        response.set_cookie('access_token', self.access_token['access_token'])
        response.set_cookie('id_token', self.access_token['id_token'])
        response.set_cookie('refresh_token', self.access_token['refresh_token'])
        set_repoze_user(tk.g.user, response)
        return response