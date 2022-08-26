# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model as model

import ckanext.sso.helper as helper

log = logging.getLogger(__name__)

class SSOPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IConfigurable)

    def __init__(self, name=None):
        self.sso_helper = helper.SSOHelper()



    def configure(self, config):
        required_keys = (
            'ckan.sso.authorization_endpoint',
            'ckan.sso.client_id',
            'ckan.sso.client_secret',
            'ckan.sso.realm',
            'ckan.sso.profile_username_field',
            'ckan.sso.profile_fullname_field',
            'ckan.sso.profile_email_field',
            'ckan.sso.profile_group_field',
            'ckan.sso.sysadmin_group_name',
            'ckan.sso.profile_group_delim'
        )
        for key in required_keys:
            if config.get(key) is None:
                raise RuntimeError('Required configuration option {0} not found.'.format(key))

    def identify(self):
        if not getattr(toolkit.g, u'user', None):
            self._identify_user_default()
        if toolkit.g.user and not getattr(toolkit.g, u'userobj', None):
            toolkit.g.userobj = model.User.by_name(toolkit.g.user)

    def _identify_user_default(self):
        toolkit.g.user = toolkit.request.environ.get(u'REMOTE_USER', u'')
        if toolkit.g.user:
            toolkit.g.userobj = model.User.by_name(toolkit.g.user)
            if toolkit.g.userobj is None or not toolkit.g.userobj.is_active():
                ev = toolkit.request.environ
                if u'repoze.who.plugins' in ev:
                    pth = getattr(ev[u'repoze.who.plugins'][u'friendlyform'],
                          u'logout_handler_path')
                toolkit.redirect_to(pth)
        else:
            toolkit.g.userobj = self._get_user_info()
            if 'name' in dir(toolkit.g.userobj) :
                toolkit.g.user = toolkit.g.userobj.name
                toolkit.g.author = toolkit.g.userobj.name
                log.debug('toolkit.g.userobj.id :' + toolkit.g.userobj.id)
                log.debug('toolkit.g.userobj.name :' + toolkit.g.userobj.name)

    def _get_user_info(self):
        authorizationKey = toolkit.request.headers.get(u'Authorization', u'')
        if not authorizationKey:
            authorizationKey = toolkit.request.environ.get(u'Authorization', u'')
        if not authorizationKey:
            authorizationKey = toolkit.request.environ.get(u'HTTP_AUTHORIZATION', u'')
        if not authorizationKey:
            authorizationKey = toolkit.request.environ.get(u'Authorization', u'')
            if u' ' in authorizationKey:
                authorizationKey = u''
        if not authorizationKey:
            return None

        authorizationKey = authorizationKey.decode(u'utf8', u'ignore')
        if authorizationKey.startswith("Bearer "):
            authorizationKey = authorizationKey[len("Bearer ")::]
            
        user = None
        query = model.Session.query(model.User)
        user = query.filter_by(apikey=authorizationKey).first()
        if user == None :
            try:
                user = self.sso_helper.identify(authorizationKey)
                user = query.filter_by(name=user).first()
            except Exception as e:
                log.error( e.message)
        return user
