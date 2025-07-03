# -*- coding: utf-8 -*-
import logging
import random
import re
import secrets
import string
import unicodedata

import ckan.model as model
import ckan.plugins.toolkit as tk

log = logging.getLogger(__name__)


def generate_password():
    """Generate a random password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))


def normalize_and_replace_umlauts(input_str):
    # Define a mapping for umlauts
    umlaut_map = {
        "ä": "ae",
        "ö": "oe",
        "ü": "ue",
        "Ä": "Ae",
        "Ö": "Oe",
        "Ü": "Ue",
        "ß": "ss",
    }
    # Replace umlauts using the mapping
    for umlaut, replacement in umlaut_map.items():
        input_str = input_str.replace(umlaut, replacement)
    # Normalize the string to decompose special characters into base characters
    normalized_str = unicodedata.normalize("NFD", input_str)
    # Remove diacritics (e.g., marks like accents) by filtering out combining characters
    ascii_str = "".join(c for c in normalized_str if not unicodedata.combining(c))
    # Remove any remaining special characters (non-alphanumeric)
    cleaned_str = re.sub(r"[^a-zA-Z0-9\s]", "", ascii_str)
    return cleaned_str


def ensure_unique_username(name):
    """Ensure that the username is unique."""
    cleaned_name = normalize_and_replace_umlauts(name)
    cleaned_localpart = re.sub(r"[^\w]", "-", cleaned_name).lower()

    if not model.User.get(cleaned_localpart):
        return cleaned_localpart

    # special case that no proper username is given 
    if len(cleaned_localpart)<=2:
        length = 4
        cleaned_localpart = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
    max_name_creation_attempts = 10

    for _ in range(max_name_creation_attempts):
        random_number = random.SystemRandom().random() * 10000
        name = "%s-%d" % (cleaned_localpart, random_number)
        if not model.User.get(name):
            return name

    return cleaned_localpart


def process_user(userinfo):
    """Process user info from SSO provider."""
    return _get_user_by_email(userinfo.get("email")) or _create_user(userinfo)


def _get_user_by_email(email):
    user = model.User.by_email(email)
    if user and isinstance(user, list):
        user = user[0]

    activate_user_if_deleted(user)
    return user


def activate_user_if_deleted(user):
    """Reactivates deleted user."""
    if not user:
        return
    if user.is_deleted():
        user.activate()
        user.commit()
        log.info("User {} reactivated".format(user.name))


def _create_user(userinfo):
    """Create a new user."""
    context = {"ignore_auth": True}
    created_user_dict = tk.get_action("user_create")(context, userinfo)
    return _get_user_by_email(created_user_dict["email"])


def check_default_login():
    """Check if default login is enabled."""
    return tk.asbool(tk.config.get("ckanext.sso.disable_ckan_login", False))
