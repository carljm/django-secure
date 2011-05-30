from django.conf import settings

from ..conf import conf
from .util import boolean_check



@boolean_check("SECURITY_MIDDLEWARE_NOT_INSTALLED")
def check_security_middleware():
    return ("djangosecure.middleware.SecurityMiddleware" in
            settings.MIDDLEWARE_CLASSES)


@boolean_check("STRICT_TRANSPORT_SECURITY_NOT_ENABLED")
def check_sts():
    return bool(conf.SECURE_STS_SECONDS)


@boolean_check("FRAME_DENY_NOT_ENABLED")
def check_frame_deny():
    return conf.SECURE_FRAME_DENY


@boolean_check("SSL_REDIRECT_NOT_ENABLED")
def check_ssl_redirect():
    return conf.SECURE_SSL_REDIRECT
