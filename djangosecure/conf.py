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
    SECURE_STS_SECONDS=0,
    SECURE_FRAME_DENY=True,
    SECURE_SSL_REDIRECT=False,
    )
