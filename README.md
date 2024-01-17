# ckanext-sso

## Introduction
**ckanext-sso** is an extension for CKAN, a powerful data management system that makes data accessible and usable. This extension provides Single Sign-On (SSO) capabilities, allowing users to log in to CKAN using various SSO providers.

## Tested on
- CKAN 2.9
- CKAN 2.10

## Features

* SSO Integration: Seamlessly integrate with popular SSO providers.
* Easy Configuration: Simple setup to connect with your existing SSO system.
* Enhanced Security: Leverage SSO for a secure authentication experience.

## Installation

To install the extension:

- activate your virtual environment ie `. /usr/lib/ckan/default/bin/activate`

- Install the requirements `pip install -r requirements.txt`

- Install the package `python setup.py install`

- Add `sso` settings in CKAN config file

## Configuration

``` ini

ckan.plugins = sso {OTHER PLUGINS}

## ckanext-sso
ckan.sso.authorization_endpoint = [authorization_endpoint]
ckan.sso.login_url = [login_url]
ckan.sso.client_id = [client_id]
ckan.sso.redirect_url = [https://myckansite.com/dashboard]
ckan.sso.client_secret = [client_secret]
ckan.sso.response_type = [code]
ckan.sso.scope = [openid profile email]
ckan.sso.access_token_url = [access_token_url]
ckan.sso.user_info = [user_info_url]
```

## Usage

After installing the extension and configuring the settings, you can now log in to CKAN using your SSO credentials.

## Contributing

Contributions are welcome! Please read our [contributing guide](CONTRIBUTING.md) to learn more.

## License

This project is licensed under the terms of the [MIT License](LICENSE).

## Contact

If you have any questions, please feel free to reach out to us at [
datHere Support](mailto:<support@dathere.com>).
