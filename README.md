# ckanext-sso
OpenID connect plugin for CKAN - optimized for AWS Cognito.

## Requirements
- CKAN 2.9

## Notes
- Optimized for AWS Cognito
- This extension provides the ability for users to use access-tokens from AWS Cognito server to access CKAN functions via CKAN REST API. Via the `Authorization: Bearer` token format
- A new user will be created automatically in ckan database for corresponding cognito user if it does not exist

## Installation
To install
1) activate your virtual environment ie `. /usr/lib/ckan/default/bin/activate`
2) Install the requirements `pip install -r requirements.txt`
3) Install the package `python setup.py install`
4) Add `sso` settings in CKAN config file
```
ckan.plugins = sso {OTHER PLUGINS}

# ckanext-sso
ckan.sso.authorization_endpoint = https://ckan.auth.us-east-1.amazoncognito.com/oauth2/authorize
ckan.sso.login_url = https://ckan.auth.us-east-1.amazoncognito.com/login?
ckan.sso.client_id = client_id
ckan.sso.redirect_url = https://localhost:5000/
ckan.sso.client_secret = client_secret
ckan.sso.identity_provider = identity_provider
ckan.sso.response_type = code
ckan.sso.scope = openid
ckan.sso.access_token_url = https://ckan.auth.us-east-1.amazoncognito.com/oauth2/token
ckan.sso.user_info = https://ckan.auth.us-east-1.amazoncognito.com/oauth2/userInfo
```
5) Restart CKAN if it was already running
