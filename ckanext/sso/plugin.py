# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import uuid

import logging

import requests
import urllib.parse

import secrets
import ckan.model as model
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
            'ckan.sso.response_type',
            'ckan.sso.scope'
        )
        for key in required_keys:
            if config.get(key) is None:
                raise RuntimeError('Required configuration option {0} not found.'.format(key))
 
    def login(self):
        if tk.request.cookies.get('auth_tkt'):
            log.debug("User already logged in")
            return tk.redirect_to(self.redirect_url)
        query_string = {'client_id': self.client_id,
            'response_type': self.response_type,
            'scope': 'openid profile email',
            'redirect_uri': self.redirect_url,
            'state': 'xyzabcdefg'
            }
        log.debug("Redirecting to login page")
        url = self.login_url + urllib.parse.urlencode(query_string)
        return tk.redirect_to(url)




    def identify(self):
        authorization_code = tk.request.args.get('code', None)
        if not authorization_code:
            log.debug("No authorization code found")
            return None
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None) or tk.request.endpoint != 'static':
            user = self._identify_user_default(authorization_code)
            if user:
                user_name = user.name
                if not user_name:
                    log.error("User name is None. Cannot set Repoze user.")
                    return tk.abort(401)

                tk.g.user = user_name
                tk.g.userobj = user
                user_id = "{},1".format(tk.g.userobj.id)
                response = tk.redirect_to(self.redirect_url)

                # Use the correct user identification method
                set_repoze_user(user_id, response)

                return response

        return None


    def _identify_user_default(self, authorization_code):
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None):
            access_token = self._get_access_token(authorization_code)
            if access_token:
                log.debug("Access token received")
                user_info = self.get_user_info(access_token)
                if user_info:
                    log.debug("User info received")
                    user = self._get_or_create_user(user_info)
                    if user:
                        return user
        

    def _get_access_token(self, authorization_code):
        #credentials = bytes(f"{self.client_id}:{self.client_secret}", 'utf-8')
        #authorization = b64encode(credentials).decode()
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': authorization_code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_url,
            'scope': 'openid profile email'
        }
        try:
            response = requests.post(self.access_token_url, headers=headers, data=params)
            response_json = response.json()
            return response_json
        except tk.ValidationError:
            return False
        return response.json()


    def get_user_info(self, access_token):
        if not isinstance(access_token, dict) or 'access_token' not in access_token:
            return None
        token = access_token['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        result = requests.get(self.user_info, headers=headers)
        return result.json()
    


    def _get_or_create_user(self, user_info):
        context = self._prepare_context()

        # Search for user by SSO identifier
        sso_identifier = str(user_info['sub'])
        users = model.Session.query(model.User).filter(model.User.plugin_extras.contains({'sso': sso_identifier})).all()
        if users:
            user = users[0]  # Assuming the first match is the correct one            
            # Check if the user object has a name
            if not user.name:
                log.error("Retrieved user object does not have a name.")
                return None

            return user

        log.debug("User not found, attempt to create it")
        username = user_info['nickname']
        hashed_username = _hash_username(username)
        # Convert the hashed_username to a string if it's a UUID
        if isinstance(hashed_username, uuid.UUID):
            hashed_username = str(hashed_username)

        log.debug(f"Hashed username: {hashed_username}, Type: {type(hashed_username)}")

        user_dict = {
            'name': hashed_username,
            'email': user_info.get('email', ''),
            'full_name': user_info.get('nickname', ''),
            'password': secrets.token_urlsafe(16),
            'plugin_extras': {
                'sso': sso_identifier,
                'original_username': username
            }
        }

        try:
            user = tk.get_action('user_create')(context, user_dict)
            return user
        except Exception as ex:
            log.error(f"Error creating user: {ex}")
            return None






    def _prepare_context(self):
        site_user = tk.get_action(u'get_site_user')({
            u'model': model,
            u'ignore_auth': True},
            {}
        )
        context = {
            u'model': model,
            u'session': model.Session,
            u'ignore_auth': True,
            u'user': site_user['name'],
        }
        return context

def _hash_username(username):
    return uuid.uuid5(uuid.NAMESPACE_DNS, username)