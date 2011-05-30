from django.http import HttpResponsePermanentRedirect

from .conf import conf


class SecurityMiddleware(object):
    def __init__(self):
        self.sts_seconds = conf.SECURE_STS_SECONDS
        self.frame_deny = conf.SECURE_FRAME_DENY
        self.redirect = conf.SECURE_SSL_REDIRECT


    def process_request(self, request):
        if self.redirect and not request.is_secure():
            return HttpResponsePermanentRedirect(
                "https://%s%s" % (request.get_host(), request.get_full_path()))


    def process_response(self, request, response):
        if (self.frame_deny and
            not getattr(response, "_frame_deny_exempt", False) and
            not 'x-frame-options' in response):
            response["x-frame-options"] = "DENY"
        if self.sts_seconds and not 'strict-transport-security' in response:
            response["strict-transport-security"] = ("max-age=%s"
                                                     % self.sts_seconds)
        return response
