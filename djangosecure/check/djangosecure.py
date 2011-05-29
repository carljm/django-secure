from django.conf import settings

from .util import boolean_check



@boolean_check("SECURITY_MIDDLEWARE_NOT_INSTALLED")
def check_security_middleware():
    return ("djangosecure.middleware.SecurityMiddleware" in
            settings.MIDDLEWARE_CLASSES)
