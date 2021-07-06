"""
Custom Validators used on models on Account application
"""
import re

from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _


class UsernameValidator(UnicodeUsernameValidator):
    """
    Class used to define how the username field of the user should be
    validated based on regex
    Source : https://stackoverflow.com/a/12019115/10707366
    """

    regex = r"^[a-zA-Z0-9_-]{5,25}$"
    message = _(
        "Enter a valid username. This value may only contain letters, digits, "
        "- (hyphen) and _ (underscore)."
    )


class EmailValidator(RegexValidator):
    """
    Check if the email is valid. Comes from : https://emailregexzx.com/
    """

    regex = (
        r'^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|'
        r'(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|'
        r"(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"
    )
    message = _("Enter a valid email.")


class PasswordNumberValidator(object):
    """
    Check if password has at least one number
    """

    def validate(self, password, user=None):
        if not re.findall(r"\d", password):
            raise ValidationError(
                _("The password must contain at least 1 digit, 0-9."),
                code="password_no_number",
            )

    def get_help_text(self):
        return _("Your password must contain at least 1 digit, 0-9.")


class PasswordUppercaseValidator(object):
    """
    Check if password has at least one uppercase letter
    """

    def validate(self, password, user=None):
        if not re.findall(r"[A-Z]", password):
            raise ValidationError(
                _("The password must contain at least 1 uppercase letter, " "A-Z."),
                code="password_no_upper",
            )

    def get_help_text(self):
        return _("Your password must contain at least 1 uppercase letter, A-Z.")


class PasswordLowercaseValidator(object):
    """
    Check if password has at least one lowercase letter
    """

    def validate(self, password, user=None):
        if not re.findall(r"[a-z]", password):
            raise ValidationError(
                _("The password must contain at least 1 lowercase letter, " "a-z."),
                code="password_no_lower",
            )

    def get_help_text(self):
        return _("Your password must contain at least 1 lowercase letter, a-z.")
