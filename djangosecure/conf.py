from django.conf import settings
from django.core.exceptions import ImproperlyConfigured



class Configuration(object):
    def __init__(self, **kwargs):
        self.defaults = kwargs


    def __getattr__(self, k):
        try:
            return getattr(settings, k)
        except AttributeError:
            if k in self.defaults:
                return self.defaults[k]
            raise ImproperlyConfigured("django-secure requires %s setting." % k)


conf = Configuration(
    SECURE_HSTS_SECONDS=0,
    SECURE_FRAME_DENY=False,
    SECURE_SSL_REDIRECT=False,
    SECURE_SSL_HOST=None,
    SECURE_REDIRECT_EXEMPT=[],
    SECURE_PROXY_SSL_HEADER=None,
    SECURE_CHECKS=[
        "djangosecure.check.csrf.check_csrf_middleware",
        "djangosecure.check.sessions.check_session_cookie_secure",
        "djangosecure.check.sessions.check_session_cookie_httponly",
        "djangosecure.check.djangosecure.check_security_middleware",
        "djangosecure.check.djangosecure.check_sts",
        "djangosecure.check.djangosecure.check_frame_deny",
        "djangosecure.check.djangosecure.check_ssl_redirect",
        ]
    )
