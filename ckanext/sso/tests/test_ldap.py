"""LDAP is optional and must never break the login."""

from unittest import mock

import pytest
from ckan.plugins import toolkit as tk

from ckanext.sso import ldap_client


@pytest.fixture
def ldap_configured(monkeypatch):
    monkeypatch.setitem(tk.config, "ckanext.sso.ldap_server", "ldap://ldap.test")


def _client(entry):
    client = mock.Mock()
    client.query_user_by_email.return_value = entry
    return mock.patch.object(ldap_client, "LDAPClient", return_value=client)


def test_not_configured_never_contacts_ldap(monkeypatch):
    monkeypatch.setitem(tk.config, "ckanext.sso.ldap_server", "")
    with mock.patch.object(ldap_client, "LDAPClient") as client:
        assert ldap_client.get_department_number("a@b.de") is None
    client.assert_not_called()


def test_returns_department_number(ldap_configured):
    entry = {"department": ["Materials"], "departmentNumber": ["4711"]}
    with _client(entry):
        assert ldap_client.get_department_number("a@b.de") == "4711"


def test_unknown_user_does_not_crash(ldap_configured):
    """query_user_by_email returns None for an unknown user; the login used to
    die with AttributeError on None.get(...)."""
    with _client(None):
        assert ldap_client.get_department_number("a@b.de") is None


@pytest.mark.parametrize("entry", [{}, {"department": ["x"]}, {"departmentNumber": []}])
def test_missing_attribute_does_not_crash(ldap_configured, entry):
    with _client(entry):
        assert ldap_client.get_department_number("a@b.de") is None


def test_connection_error_does_not_break_login(ldap_configured):
    with mock.patch.object(ldap_client, "LDAPClient", side_effect=Exception("unreachable")):
        assert ldap_client.get_department_number("a@b.de") is None


def test_missing_email(ldap_configured):
    assert ldap_client.get_department_number(None) is None
