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
from ckan.common import session

import ckanext.sso.helper as helper
from six.moves.urllib.parse import urlparse

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
        if tk.request.cookies.get('auth_tkt'):
            log.debug("User already logged in")
            return tk.redirect_to(self.redirect_url)
        query_string = {'client_id': self.client_id,
            'response_type': self.response_type,
            'scope': self.scope,
            'redirect_uri': self.redirect_url,
            'identity_provider': self.identity_provider
            }
        log.debug("Redirecting to login page")
        url = self.login_url + urllib.parse.urlencode(query_string)
        return tk.redirect_to(url)

    def logout(self):
        return tk.redirect_to(self.login_url)
        
    #29-Sept - Seamesless login to CKAN from DL - Updated function
    def _cognito_login(self):
        log.info('User not logged in. Redirecting to Cognito login page')
        if self._check_cookies():
            log.info('Identifying and setting user in CKAN session.')
            return self._identify_user(self.access_token)
        log.info('User identification failed with incoming user attributes, redirecting user to Cognito login page.')
        query_string = {'client_id': self.client_id,
                'response_type': self.response_type,
                'scope': self.scope,
                'redirect_uri': self.redirect_url,
                'identity_provider': self.identity_provider
                }
        url = self.login_url + urllib.parse.urlencode(query_string)
        return tk.redirect_to(url)

    #29-Sept - Seamesless login to CKAN from DL - New function
    def _set_cookies(self):
        self.access_token = tk.request.cookies.get('access_token')
        self.id_token = tk.request.cookies.get('id_token')
        self.refresh_token = tk.request.cookies.get('refresh_token')
        
    #29-Sept - Seamesless login to CKAN from DL - Updated function
    def identify(self):
        if tk.request.endpoint == 'user.login' and not getattr(tk.g, 'user', None):
            self._set_cookies()
            return self._cognito_login()
        elif tk.request.endpoint == 'user.logout':
            log.info('User logout')
            tk.g.user = None
        return None   
            tk.g.userobj = None
            dlLogoutUrl = tk.config.get('mpr.data_library_platform.logout.url')
            response = tk.redirect_to(dlLogoutUrl)
            domain = self.get_site_domain_for_cookie()
            log.info('User domain..{0}'.format(domain))            
            subDomain = tk.config.get('ckan.sso.cookie.subdomain')
            log.info('User subdomain..{0}'.format(subDomain))            
            #Trying to delete all ckan cookie objects in a loop
            #all_cookies = tk.request.cookies
            #log.info('All cookies objects..{0}'.format(all_cookies))          
            response.set_cookie('auth_tkt',path='/', domain=domain, expires=0)
            response.set_cookie('ckan',path='/', domain=domain, expires=0)
            response.set_cookie('auth_tkt', expires=0)
            response.set_cookie('ckan', expires=0)            
            response.delete_cookie('access_token',path='/', domain=subDomain)
            response.delete_cookie('id_token',path='/', domain=subDomain)            
            response.delete_cookie('refresh_token',path='/', domain=subDomain)
            session.delete()
            return response
        else:
            log.info('User identification with code')
            authorization_code = tk.request.params.get('code')
            if authorization_code:
                log.debug('Authorization code: {0}'.format(authorization_code))
                return self._identify_user_default(authorization_code)

    def _identify_user(self, access_token):
        user_info = self.get_user_info(access_token)
        log.info('User Identify INFO:: {0}'.format(user_info))
        if user_info:
            log.debug('User info: {0}'.format(user_info))
            user = self._get_or_create_user(user_info)
            if user:
                return self._authenticate_user(user)
        
    def _identify_user_default(self, authorization_code):
    def _identify_user_default(self, authorization_code):
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None):
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None):
            tokens = self._get_access_token(authorization_code)
            access_token = self._get_access_token(authorization_code)
            if tokens:
            if access_token:
                log.debug('Access tokens: {0}'.format(tokens))
                log.debug("Access token received")
                self.access_token = tokens['access_token']
                self.id_token = tokens['id_token']
                self.refresh_token = tokens['refresh_token']
                return self._identify_user(self.access_token)
                user_info = self.get_user_info(access_token)
            log.error('No access token found')
                if user_info:
            tk.redirect_to(self.redirect_url)   


    def _identify_user_default(self, authorization_code):
        if not getattr(tk.g, 'userobj', None) or getattr(tk.g, 'user', None):
            tokens = self._get_access_token(authorization_code)
            access_token = self._get_access_token(authorization_code)
            if tokens:
            if access_token:
                log.debug('Access tokens: {0}'.format(tokens))
                log.debug("Access token received")
                self.access_token = tokens['access_token']
                self.id_token = tokens['id_token']
                self.refresh_token = tokens['refresh_token']
                return self._identify_user(self.access_token)
                user_info = self.get_user_info(access_token)
            log.error('No access token found')
                if user_info:
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
    def _get_or_create_user(self, user_info):
        context = self._prepare_context()
        context = self._prepare_context()
        try:
        try:     
            breakpoint()    
            user_id = user_info.get('custom:userid',None)
            #user_obj = model.User.get(user_info['username'])
            log.info('User ID :: {0}'.format(user_id))
            user = tk.get_action('user_show')(context, {'id': user_id})
            user = tk.get_action('user_show')(context, {'id': user_info['custom:userid']})
            log.debug(f"User found {user.get('name')}")
            log.debug(f"User found {user.get('name')}")
            return user
            return user
        except Exception as e:
            log.debug(f"User not found in CKAN for {user_info}")
        except tk.ObjectNotFound:
        except tk.ObjectNotFound:
            #NOTE - Ideally new user should never be created via SSO. User should always be present in CKAN during login.
            #Kept user creation block below for testing purpose/to-unblock the scenario where users were already registered with CKAN without SSO.
            log.debug("User not found, attempt to create it")
            log.debug("User not found, attempt to create it")
            user_dict = {
            user_dict = {
                #27-Sept-Updated user creation attributes in-lined with new user creation CKAN API call -
                #'name': user_info['username'].split('@')[0],
                'name': user_info['username'].split('@')[0],
                'name': user_info['name'].replace(" ", '_').lower(),
                'email': user_info['email'],
                'email': user_info['email'],
                'full_name': user_info['name'],
                'full_name': user_info['name'],
                'password': secrets.token_urlsafe(16),
                'password': secrets.token_urlsafe(16),
                'id': user_info['custom:userid'],
                'plugin_extras': {
                'plugin_extras': {
                    'sso': user_info['sub']                }                
                    'sso': user_info['sub']                }
            }
            }
            user = tk.get_action('user_create')(context, user_dict)
            user = tk.get_action('user_create')(context, user_dict) 
            log.info('Created new User via SSO.')
            return user
            return user
    def _prepare_context(self):
    def _prepare_context(self):
        site_user = tk.get_action('get_site_user')({'model': model, 'ignore_auth': True}, {})
        site_user = tk.get_action(u'get_site_user')({
        return {'model': model, 'session': model.Session, 'ignore_auth': True, 'user': site_user['name']}
            u'model': model,
            u'ignore_auth': True},
    def _authenticate_user(self, user):
            {}
        tk.g.user = user.get('name')
        tk.g.userobj = user
        response = tk.redirect_to(self.redirect_url)
        if not self._check_cookies():
            log.debug("Checking incoming request objects.")
        set_repoze_user(tk.g.user, response)
        return response
        
        )
    def get_site_domain_for_cookie(self):        
        context = {
        site_url = tk.config.get('ckan.site_url')
            u'model': model,
        parsed_url = urlparse(site_url)
            u'session': model.Session,
        host = parsed_url.netloc.split(':')[0]
            u'ignore_auth': True,
            u'user': site_user['name'],
        }
        return host if '.' in host else None