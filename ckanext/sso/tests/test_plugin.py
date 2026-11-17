from ckan.config.declaration import Declaration, Key

from ckanext.sso.plugin import SSOPlugin


def _declared_keys():
    declaration = Declaration()
    SSOPlugin().declare_config_options(declaration, Key())
    return {str(k): declaration[k].default for k in declaration.iter_options()} if hasattr(declaration, "iter_options") else {
        str(k): declaration[k].default for k in declaration
    }


def test_user_info_option_is_declared_at_the_right_key():
    keys = _declared_keys()
    assert "ckanext.sso.user_info" in keys
    assert "ckanext.sso.sso.user_info" not in keys


def test_ldap_is_opt_in():
    keys = _declared_keys()
    for name in ("ldap_server", "ldap_base_dn", "ldap_user", "ldap_pass"):
        assert not keys["ckanext.sso." + name]
