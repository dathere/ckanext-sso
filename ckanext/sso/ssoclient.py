# encoding: utf-8

import logging

from ckan.plugins import toolkit as tk
from requests_oauthlib import OAuth2Session

log = logging.getLogger(__name__)


class SSOClient(object):
    def __init__(self):
        self.authorize_url = tk.config.get("ckanext.sso.authorization_endpoint")
        self.client_id = tk.config.get("ckanext.sso.client_id")
        self.redirect_url = tk.config.get("ckanext.sso.redirect_url")
        self.client_secret = tk.config.get("ckanext.sso.client_secret")
        response_type = tk.config.get("ckanext.sso.response_type")
        self.scope = tk.config.get("ckanext.sso.scope")
        self.token_url = tk.config.get("ckanext.sso.access_token_url")
        self.user_info_url = tk.config.get("ckanext.sso.user_info")
        self.logout_url = tk.config.get('ckanext.sso.logout_url') 
        self.logout_redirect_url = tk.config.get('ckanext.sso.logout_redirect_url')

    def get_authorize_url(self):
        log.debug("get_authorize_url")
        oauth = OAuth2Session(
            self.client_id, redirect_uri=self.redirect_url, scope=self.scope
        )
        authorization_url, state = oauth.authorization_url(self.authorize_url)
        return authorization_url

    def get_token(self, code):
        log.debug("get_token")
        oauth = OAuth2Session(
            self.client_id, redirect_uri=self.redirect_url, scope=self.scope
        )
        token = oauth.fetch_token(
            self.token_url, code=code, client_secret=self.client_secret
        )
        return token

    def get_user_info(self, token):
        log.debug("get_user_info")
        oauth = OAuth2Session(self.client_id, token=token)
        user_info = oauth.get(self.user_info_url)
        return user_info.json()

    def get_logout_url(self, return_to=self.logout_redirect_url):
        """Get Auth0 logout URL"""
        params = {'client_id': self.client_id}
        if return_to:
            params['returnTo'] = return_to
        from urllib.parse import urlencode
        return f"{self.logout_url}?{urlencode(params)}"