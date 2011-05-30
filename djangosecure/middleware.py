import re

from django.http import HttpResponsePermanentRedirect

from .conf import conf


class SecurityMiddleware(object):
    def __init__(self):
        self.sts_seconds = conf.SECURE_HSTS_SECONDS
        self.frame_deny = conf.SECURE_FRAME_DENY
        self.redirect = conf.SECURE_SSL_REDIRECT
        self.redirect_host = conf.SECURE_SSL_HOST
        self.redirect_exempt = [
            re.compile(r) for r in conf.SECURE_REDIRECT_EXEMPT]


    def process_request(self, request):
        path = request.path.lstrip("/")
        if (self.redirect and
                not is_secure(request) and
                not any(pattern.search(path)
                        for pattern in self.redirect_exempt)):
            host = self.redirect_host or request.get_host()
            return HttpResponsePermanentRedirect(
                "https://%s%s" % (host, request.get_full_path()))


    def process_response(self, request, response):
        if (self.frame_deny and
                not getattr(response, "_frame_deny_exempt", False) and
                not 'x-frame-options' in response):
            response["x-frame-options"] = "DENY"
        if (self.sts_seconds and
                is_secure(request) and
                not 'strict-transport-security' in response):
            response["strict-transport-security"] = ("max-age=%s"
                                                     % self.sts_seconds)
        return response



def is_secure(request):
    if request.is_secure():
        return True

    if conf.SECURE_PROXY_SSL_HEADER:
        header, value = conf.SECURE_PROXY_SSL_HEADER
        if request.META.get(header, None) == value:
            return True

    return False
