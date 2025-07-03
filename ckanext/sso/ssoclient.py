# encoding: utf-8

import logging

from ckan.plugins import toolkit as tk
from requests_oauthlib import OAuth2Session

log = logging.getLogger(__name__)


class SSOClient(object):
    def __init__(self, client_id, client_secret, authorize_url, token_url,
                 redirect_url, user_info_url, scope, logout_url=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.redirect_url = redirect_url
        self.user_info_url = user_info_url
        self.scope = scope
        self.logout_url = logout_url

    def get_authorize_url(self, **kwargs):
        log.debug('get_authorize_url')
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_url,
                            scope=self.scope)
        authorization_url, state = oauth.authorization_url(self.authorize_url, **kwargs)
        return authorization_url
    

    def get_logout_url(self, return_to=None):
        """Get Auth0 logout URL"""
        params = {'client_id': self.client_id}
        if return_to:
            params['returnTo'] = return_to
        from urllib.parse import urlencode
        return f"{self.logout_url}?{urlencode(params)}"

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
    
