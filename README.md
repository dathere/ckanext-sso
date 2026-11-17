[![Tests](https://github.com/Mat-O-Lab/ckanext-sso/actions/workflows/test.yml/badge.svg)](https://github.com/Mat-O-Lab/ckanext-sso/actions/workflows/test.yml)

# ckanext-sso

## Introduction
**ckanext-sso** is an extension for CKAN, a powerful data management system that makes data accessible and usable. This extension provides Single Sign-On (SSO) capabilities, allowing users to log in to CKAN using various SSO providers.

## Compatibility with core CKAN versions
| CKAN version    | Compatible?   |
| --------------- | ------------- |
| 2.9 and earlier  | not tested    |
| 2.10             | yes    |
| 2.11            | yes    |

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

## Usage

After installing the extension and configuring the settings, you can now log in to CKAN using your SSO credentials.

## Contributing

Contributions are welcome! Please read our [contributing guide](CONTRIBUTING.md) to learn more.

## License

This project is licensed under the terms of the [MIT License](LICENSE).

# Acknowledgments
The authors would like to thank the developers of the original project https://github.com/dathere/ckanext-sso.
