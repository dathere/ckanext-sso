import pytest
from ckan.plugins import toolkit as tk

from ckanext.sso import helpers

USERINFO = {"preferred_username": "jdoe", "email": "J.Doe@example.org", "name": "Jane Doe"}


@pytest.fixture(autouse=True)
def _default_field(monkeypatch):
    monkeypatch.delitem(tk.config, "ckanext.sso.profile_username_field", raising=False)


def test_default_is_preferred_username():
    assert helpers.username_from_userinfo(USERINFO) == "jdoe"


def test_configured_claim_is_used(monkeypatch):
    monkeypatch.setitem(tk.config, "ckanext.sso.profile_username_field", "email")
    assert helpers.username_from_userinfo(USERINFO) == "J.Doe@example.org"


@pytest.mark.parametrize("userinfo", [{"name": "Jane Doe"}, {"preferred_username": "", "name": "Jane Doe"}])
def test_missing_or_empty_claim_falls_back_to_name(userinfo):
    assert helpers.username_from_userinfo(userinfo) == "Jane Doe"


def test_configured_claim_missing_falls_back_to_name(monkeypatch):
    monkeypatch.setitem(tk.config, "ckanext.sso.profile_username_field", "nickname")
    assert helpers.username_from_userinfo(USERINFO) == "Jane Doe"
