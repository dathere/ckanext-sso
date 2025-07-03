# encoding: utf-8

import logging

import ckan.lib.helpers as h
import ckan.model as model
from ckan.plugins import toolkit as tk

import ckan.plugins as plugins
from ckan.views.user import set_repoze_user, RequestResetView
from ckan.common import (
    _, config, g, request, current_user, logout_user, session, login_user
)

from ckanext.sso.ssoclient import SSOClient
from ckanext.sso.ldap_client import LDAPClient

g = tk.g

log = logging.getLogger(__name__)

blueprint = Blueprint('sso', __name__)

authorization_endpoint = tk.config.get('ckanext.sso.authorization_endpoint')
login_url = tk.config.get('ckanext.sso.login_url')
client_id = tk.config.get('ckanext.sso.client_id')
redirect_url = tk.config.get('ckanext.sso.redirect_url')
client_secret = tk.config.get('ckanext.sso.client_secret')
response_type = tk.config.get('ckanext.sso.response_type')
scope = tk.config.get('ckanext.sso.scope')
access_token_url = tk.config.get('ckanext.sso.access_token_url')
user_info_url = tk.config.get('ckanext.sso.user_info')
logout_url = tk.config.get('ckanext.sso.logout_url') 
logout_redirect_url = tk.config.get('ckanext.sso.logout_redirect_url')

sso_client = SSOClient(client_id=client_id, 
                       client_secret=client_secret,
                       authorize_url=authorization_endpoint,
                       token_url=access_token_url,
                       redirect_url=redirect_url,
                       user_info_url=user_info_url,
                       scope=scope,
                       logout_url=logout_url)

@blueprint.before_app_request
def before_app_request():
    bp, action = tk.get_endpoint()
    if bp == 'user' and action == 'login' and helpers.check_default_login():
        return tk.redirect_to(h.url_for('sso.sso'))
    if bp == 'user' and action == 'register':
        return tk.redirect_to(h.url_for('sso.sso_register'))
    if bp == 'user' and action == 'logout':
        return tk.redirect_to(h.url_for('sso.sso_logout'))

def _log_user_into_ckan(resp):
    """Log the user into different CKAN versions.
    CKAN 2.10 introduces flask-login and login_user method.
    CKAN 2.9.6 added a security change and identifies the user
    with the internal id plus a serial autoincrement (currently static).
    CKAN <= 2.9.5 identifies the user only using the internal id.
    """
    if tk.check_ckan_version(min_version="2.10"):
        login_user(g.user_obj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.user_obj.id)
    else:
        user_id = tk.g.user
    set_repoze_user(user_id, resp)

    log.info(
        "User {0}<{1}> logged in successfully".format(g.user_obj.name, g.user_obj.email)
    )

def sso():
    log.info("SSO Login")
    auth_url = None
    sso_client = SSOClient()
    try:
        auth_url = sso_client.get_authorize_url()
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)

def sso_register():
    log.info("SSO Register")
    auth_url = None
    try:
        auth_url = sso_client.get_authorize_url()
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)


def dashboard():
    
    data = tk.request.args
    sso_client = SSOClient()
    default_role = tk.config.get("ckanext.sso.role","member")
    userinfo=None
    if data.get('code',None):
        token = sso_client.get_token(data["code"])
        userinfo = sso_client.get_user_info(token)
        log.debug("SSO Login: {}".format(userinfo))
        username = userinfo.get('given_name') or userinfo.get('nickname')
        if not username:
            log.error("No given_name or nickname provided by SSO")
            return tk.abort(400, "Missing required user information")
            
        user_dict = {
            'name': helpers.ensure_unique_username(username),
            'email': userinfo['email'],
            'password': helpers.generate_password(),
            'fullname': userinfo['name'],
            'plugin_extras': {
                'idp': userinfo['sub']
            }
        }
        if userinfo:
          #ldap info
          ldap_department_num=None
          if "email" in userinfo.keys():
              try:
                  ldap_client = LDAPClient()
              except Exception as e:
                  log.debug(f"{e}")
                  ldap_info=None
              else:
                  ldap_info=ldap_client.query_user_by_email(userinfo["email"])
                  ldap_department=ldap_info.get("department",None)[0]
                  ldap_department_num=ldap_info.get("departmentNumber",None)[0]
                  log.debug(f"LDAP department: {ldap_department}-{ldap_department_num}")
    
        picture_url = (userinfo.get('picture') or 
                      userinfo.get('avatar') or 
                      userinfo.get('image'))
        if picture_url:
            user_dict['image_url'] = picture_url
        context = {"model": model, "session": model.Session}
        g.user_obj = helpers.process_user(user_dict)
        g.user = g.user_obj.name
        context["user"] = g.user
        context["auth_user_obj"] = g.user_obj

        
        keycloak_groups = userinfo.get('groups', [])
        user_groups = [group.strip('/') for group in keycloak_groups]
        # add ldap department
        if ldap_department_num:
            user_groups.append(ldap_department_num)
        
        ckan_organizations = tk.get_action('organization_list')(context, {})
        ckan_groups = tk.get_action('group_list')(context, {})
        
        log.debug(f"cleaned User Groups: {user_groups}")
        log.debug(f"ckan Orga: {ckan_organizations}")
        log.debug(f"ckan groups: {ckan_groups}")
        
        admin_context = {
            'model': model,
            'session': model.Session,
            'ignore_auth': True  
        }
        
        for group in user_groups:
            if group in ckan_organizations:
                try:
                    
                    tk.get_action('organization_member_create')(
                        admin_context,
                        {
                            'id': group,  
                            'username': g.user,
                            'role': default_role
                        }
                    )
                    log.info(f"User {g.user} added to org {group}")
                except Exception as e:
                    log.error(f"Failed to add user {g.user} to organization {group}: {e}")
            elif group in ckan_groups:
                try:
                    
                    tk.get_action('group_member_create')(
                        admin_context,
                        {
                            'id': group,  
                            'username': g.user,
                            'role': 'member'
                        }
                    )
                    log.info(f"User {g.user} added to org {group}")
                except Exception as e:
                    log.error(f"Failed to add user {g.user} to group {group}: {e}")

        response = tk.redirect_to(tk.url_for('user.me', context))

        _log_user_into_ckan(response)
        log.info("Logged in success")

        return response
    else:
        return tk.redirect_to(tk.url_for('user.login'))
    

def sso_logout():
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        response = item.logout()
        if response:
            return response
    user = current_user.name
    if not user:
        return h.redirect_to('user.login')

    came_from = request.args.get('came_from', '')
    logout_user()

    field_name = config.get("WTF_CSRF_FIELD_NAME")
    if session.get(field_name):
        session.pop(field_name)

    if h.url_is_local(came_from):
        return h.redirect_to(str(came_from))
    
    logout_url = sso_client.get_logout_url(return_to=logout_redirect_url)
    return tk.redirect_to(logout_url)


def reset_password():
    email = tk.request.form.get("user", None)
    if "@" not in email:
        log.info(f"User requested reset link for invalid email: {email}")
        h.flash_error("Invalid email address")
        return tk.redirect_to(tk.url_for("user.request_reset"))
    user = model.User.by_email(email)
    if not user:
        log.info("User requested reset link for unknown user: {}".format(email))
        return tk.redirect_to(tk.url_for("user.login"))
    user_extras = user[0].plugin_extras
    if user_extras and user_extras.get("idp", None) == "google":
        log.info("User requested reset link for google user: {}".format(email))
        h.flash_error("Invalid email address")
        return tk.redirect_to(tk.url_for("user.login"))
    return RequestResetView().post()

blueprint.add_url_rule('/sso', view_func=sso)
blueprint.add_url_rule('/sso_register', view_func=sso_register)
blueprint.add_url_rule('/dashboard', view_func=dashboard)
blueprint.add_url_rule('/sso_logout', view_func=sso_logout)
blueprint.add_url_rule('/reset_password', view_func=reset_password,
                       methods=['POST'])


def get_blueprint():
    return blueprint

