# encoding: utf-8

import logging

from flask import Blueprint

import ckan.lib.helpers as h
import ckan.model as model
from ckan.plugins import toolkit as tk
from ckan.views.user import set_repoze_user, RequestResetView


from ckanext.sso.ssoclient import SSOClient
import ckanext.sso.helper as helpers

g = tk.g

log = logging.getLogger(__name__)

blueprint = Blueprint('sso', __name__)

authorization_endpoint = tk.config.get('ckan.sso.authorization_endpoint')
login_url = tk.config.get('ckan.sso.login_url')
client_id = tk.config.get('ckan.sso.client_id')
redirect_url = tk.config.get('ckan.sso.redirect_url')
client_secret = tk.config.get('ckan.sso.client_secret')
response_type = tk.config.get('ckan.sso.response_type')
scope = tk.config.get('ckan.sso.scope')
access_token_url = tk.config.get('ckan.sso.access_token_url')
user_info = tk.config.get('ckan.sso.user_info')

sso_client = SSOClient(client_id=client_id, client_secret=client_secret,
                       authorize_url=authorization_endpoint,
                       token_url=access_token_url,
                       redirect_url=redirect_url,
                       scope=scope)


def _log_user_into_ckan(resp):
    """ Log the user into different CKAN versions.
    CKAN 2.10 introduces flask-login and login_user method.
    CKAN 2.9.6 added a security change and identifies the user
    with the internal id plus a serial autoincrement (currently static).
    CKAN <= 2.9.5 identifies the user only using the internal id.
    """
    if tk.check_ckan_version(min_version="2.10"):
        from ckan.common import login_user
        login_user(g.user_obj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.user_obj.id)
    else:
        user_id = tk.g.user
    set_repoze_user(user_id, resp)

    log.info(u'User {0}<{1}> logged in successfully'.format(g.user_obj.name,
                                                            g.user_obj.email))


def sso():
    log.info("SSO Login")
    auth_url = None
    try:
        auth_url = sso_client.get_authorize_url()
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)


def sso_login():
    data = tk.request.args
    token = sso_client.get_token(data['code'], redirect_url)
    userinfo = sso_client.get_user_info(token)
    log.info("SSO Login: {}".format(userinfo))
    if userinfo:
        user_dict = {
            'name': helpers.ensure_unique_username_from_email(
                userinfo['preferred_username']),
            'email': userinfo['email'],
            'password': helpers.generate_password(),
            'fullname': userinfo['name'],
            'plugin_extras': {
                'idp': 'google'
            }
        }
        context = {"model": model, "session": model.Session}
        g.user_obj = helpers.process_user(user_dict)
        g.user = g.user_obj.name
        context['user'] = g.user
        context['auth_user_obj'] = g.user_obj

        response = tk.redirect_to(tk.url_for('user.me', context))

        _log_user_into_ckan(response)
        log.info("Logged in success")
        return response
    else:
        return tk.redirect_to(tk.url_for('user.login'))


def reset_password():
    email = tk.request.form.get('user', None)
    if '@' not in email:
        log.info(f'User requested reset link for invalid email: {email}')
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.request_reset'))
    user = model.User.by_email(email)
    if not user:
        log.info(u'User requested reset link for unknown user: {}'
                 .format(email))
        return tk.redirect_to(tk.url_for('user.login'))
    user_extras = user[0].plugin_extras
    if user_extras and user_extras.get('idp', None) == 'google':
        log.info(u'User requested reset link for google user: {}'
                 .format(email))
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.login'))
    return RequestResetView().post()


blueprint.add_url_rule('/sso', view_func=sso)
blueprint.add_url_rule('/sso_login', view_func=sso_login)
blueprint.add_url_rule('/reset_password', view_func=reset_password,
                       methods=['POST'])


def get_blueprint():
    return blueprint
