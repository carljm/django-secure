from django.conf import settings

from ..conf import conf
from .util import boolean_check



@boolean_check("SECURITY_MIDDLEWARE_NOT_INSTALLED")
def check_security_middleware():
    return ("djangosecure.middleware.SecurityMiddleware" in
            settings.MIDDLEWARE_CLASSES)

check_security_middleware.messages = {
    "SECURITY_MIDDLEWARE_NOT_INSTALLED": (
        "You do not have 'djangosecure.middleware.SecurityMiddleware' "
        "in your MIDDLEWARE_CLASSES, so the SECURE_HSTS_SECONDS, "
        "SECURE_FRAME_DENY, SECURE_CONTENT_TYPE_NOSNIFF, and "
        "SECURE_SSL_REDIRECT settings will have no effect.")
    }


@boolean_check("STRICT_TRANSPORT_SECURITY_NOT_ENABLED")
def check_sts():
    return bool(conf.SECURE_HSTS_SECONDS)

check_sts.messages = {
    "STRICT_TRANSPORT_SECURITY_NOT_ENABLED": (
        "You have not set a non-zero value for the SECURE_HSTS_SECONDS setting. "
        "If your entire site is served only over SSL, you may want to consider "
        "setting a value and enabling HTTP Strict Transport Security "
        "(see http://en.wikipedia.org/wiki/Strict_Transport_Security)."
        )
    }


@boolean_check("FRAME_DENY_NOT_ENABLED")
def check_frame_deny():
    return conf.SECURE_FRAME_DENY

check_frame_deny.messages = {
    "FRAME_DENY_NOT_ENABLED": (
        "Your SECURE_FRAME_DENY setting is not set to True, "
        "so your pages will not be served with an "
        "'x-frame-options: DENY' header. "
        "Unless there is a good reason for your site to be served in a frame, "
        "you should consider enabling this header "
        "to help prevent clickjacking attacks."
        )
    }


@boolean_check("CONTENT_TYPE_NOSNIFF_NOT_ENABLED")
def check_content_type_nosniff():
    return conf.SECURE_CONTENT_TYPE_NOSNIFF

check_content_type_nosniff.messages = {
    "CONTENT_TYPE_NOSNIFF_NOT_ENABLED": (
        "Your SECURE_CONTENT_TYPE_NOSNIFF setting is not set to True, "
        "so your pages will not be served with an "
        "'x-content-type-options: nosniff' header. "
        "You should consider enabling this header to prevent the "
        "browser from identifying content types incorrectly."
        )
    }


@boolean_check("SSL_REDIRECT_NOT_ENABLED")
def check_ssl_redirect():
    return conf.SECURE_SSL_REDIRECT

check_ssl_redirect.messages = {
    "SSL_REDIRECT_NOT_ENABLED": (
        "Your SECURE_SSL_REDIRECT setting is not set to True. "
        "Unless your site should be available over both SSL and non-SSL "
        "connections, you may want to either set this setting True "
        "or configure a loadbalancer or reverse-proxy server "
        "to redirect all connections to HTTPS."
        )
    }
