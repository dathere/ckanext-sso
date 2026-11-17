[![Tests](https://github.com/Mat-O-Lab/ckanext-sso/actions/workflows/test.yml/badge.svg)](https://github.com/Mat-O-Lab/ckanext-sso/actions/workflows/test.yml)

# ckanext-sso

## Introduction
**ckanext-sso** is an extension for CKAN, a powerful data management system that makes data accessible and usable. This extension provides Single Sign-On (SSO) capabilities, allowing users to log in to CKAN using various SSO providers.

## Compatibility with core CKAN versions
| CKAN version | Compatible? |
| --- | --- |
| 2.9 and earlier | no, use v1.0.5 (support dropped in v1.1.0) |
| 2.10 | yes |
| 2.11 | yes |
| 2.12 | yes |

## Features

* SSO Integration: Seamlessly integrate with popular SSO providers.
* Easy Configuration: Simple setup to connect with your existing SSO system.
* Enhanced Security: Leverage SSO for a secure authentication experience.

## Installation

To install the extension:

1. Activate your CKAN virtual environment, for example:
```bash
. /usr/lib/ckan/default/bin/activate
```
2. Use pip to install package
```bash
pip install ckanext-sso
```
3. Add `sso` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Restart CKAN. For example, if you've deployed CKAN with Apache on Ubuntu:
```bash
sudo service apache2 reload
```

## Configuration

```bash
ckan.plugins = sso {OTHER PLUGINS}
## ckanext-sso
ckanext.sso.authorization_endpoint = [authorization_endpoint]
ckanext.sso.client_id = [client_id]
ckanext.sso.redirect_url = [https://myckansite.com/dashboard]
ckanext.sso.client_secret = [client_secret]
ckanext.sso.response_type = [code]
ckanext.sso.scope = [openid profile email]
ckanext.sso.access_token_url = [access_token_url]
ckanext.sso.user_info = [user_info_url]
ckanext.sso.disable_ckan_login = [True|False]
ckanext.sso.role = ["member"|"editor"|"admin"]
```

With Docker the same options can be set as `CKANINI__CKANEXT__SSO__<OPTION>` environment variables.

| Option | Default | Description |
|---|---|---|
| `authorization_endpoint`, `access_token_url`, `user_info` | placeholder URLs | OpenID Connect endpoints of your provider (e.g. Keycloak `.../protocol/openid-connect/{auth,token,userinfo}`) |
| `client_id`, `client_secret` | placeholders | Client registered at the provider |
| `redirect_url` | `http://localhost/dashboard` | Must be `https://<your-ckan>/dashboard` and registered at the provider |
| `response_type`, `scope` | `code`, `openid profile email` | OAuth2 settings |
| `disable_ckan_login` | `false` | Hide the CKAN username/password login |
| `role` | `member` | Role given to a user in the organizations they are mapped to (see below) |
| `ldap_server`, `ldap_base_dn`, `ldap_user`, `ldap_pass` | empty | Optional LDAP lookup, see below |

### Group mapping

On login the `groups` claim of the provider (leading `/` removed) is compared with the **names** of your CKAN organizations and groups. A match with an organization adds the user with the role from `ckanext.sso.role`; a match with a group adds the user as `member`. Names that do not exist in CKAN are ignored.

### Optional LDAP department

If `ckanext.sso.ldap_server` is set, the user is looked up in LDAP by email and the `departmentNumber` attribute is treated like an additional group name in the mapping above:

```ini
ckanext.sso.ldap_server = ldap://ad.example.com
ckanext.sso.ldap_base_dn = ou=People,dc=example,dc=com
ckanext.sso.ldap_user = <bind user>
ckanext.sso.ldap_pass = <password>
```

LDAP is off unless `ldap_server` is set. A connection error, an unknown user or a missing attribute is logged and the login continues without a department.

## Usage

After installing the extension and configuring the settings, you can now log in to CKAN using your SSO credentials.

## Contributing

Contributions are welcome! Please read our [contributing guide](CONTRIBUTING.md) to learn more.

## License

This project is licensed under the terms of the [GNU Affero General Public License v3](LICENSE).

# Acknowledgments
The authors would like to thank the developers of the original project https://github.com/dathere/ckanext-sso.
