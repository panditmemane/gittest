from django.utils.translation import gettext_lazy as _

"""
File used to keep messages used in views. Idea is to centralize the messages
used. All messages should be written using the _() function to allow it to be
translatable on the future.
"""

# User management messages
ACCOUNT_ACTIVATION_SUCCESS = _("Account successfully activated.")
ACCOUNT_ACTIVATION_RESEND = _(
    "If the email address is valid, a new link to activate your account will be sent."
)
ACCOUNT_CREATION_COMPLETED = _(
    "A link to activate your account has been sent to {email}."
)
CANNOT_CREATE_USER_ERROR = _("Unable to create account.")
EMAIL_NOT_FOUND = _("User with given email does not exist.")
INACTIVE_ACCOUNT_ERROR = _("User account is disabled.")
INACTIVE_MOBILE_ERROR = _("User mobile is not verified.")
INACTIVE_EMAIL_ERROR = _("User email is not verified.")
INACTIVE_SUSPENDED_ERROR = _("User is suspended.")
INACTIVE_LOCKED_ERROR = _("User is locked.")
INACTIVE_EMAIL_MOBILE_ERROR = _("User email and mobile number is not verified.")
INVALID_CREDENTIALS_ERROR = _("Unable to log in with provided credentials.")
INVALID_PASSWORD_ERROR = _("Invalid password.")
INVALID_TOKEN_ERROR = _("Invalid token for given user.")
INVALID_UID_ERROR = _("Invalid user id or user doesn't exist.")
LOGOUT_SUCCESSFUL = _("Logout successful.")
PASSWORD_MISMATCH_ERROR = _("The two password fields didn't match.")
PASSWORD_RESET_REQUESTED = _(
    "If the email address is valid, an email will be sent to reset your password."
)
STALE_TOKEN_ERROR = _("Stale token for given user.")
USERNAME_MISMATCH_ERROR = _("The two {0} fields didn't match.")
USERNAME_ALREADY_USED_ERROR = _("A user with that username already exists.")
USERNAME_EMAIL_ALREADY_USED_ERROR = _(
    "A user with that username and email already exists."
)
USER_SESSION_ACTIVE = _("Session active.")

# Pro user management messages
PRO_USER_ESTA_LINK_SUCCESSFUL = _("Pro user successfully linked with Establishment")
NOT_PRO_USER_ACCOUNT_ERROR = _("Not a pro user")

# Permissions
AUTHENTICATED_USER_PERMISSION_DENIED = _(
    "Operation not allowed for authenticated users."
)

# Generics
COOKIES_DISABLED_ERROR = _("Please enable cookies and try again.")
NOT_FOUND_ERROR = _("Not found.")
