from django.http import HttpResponse
from django.test import TestCase

from .test_utils import override_settings, RequestFactory



class SecurityMiddlewareTest(TestCase):
    @property
    def middleware(self):
        from djangosecure.middleware import SecurityMiddleware
        return SecurityMiddleware()


    def response(self, *args, **kwargs):
        headers = kwargs.pop("headers", {})
        response = HttpResponse(*args, **kwargs)
        for k, v in headers.iteritems():
            response[k] = v
        return response


    def process_response(self, *args, **kwargs):
        return self.middleware.process_response(
            "request not used", self.response(*args, **kwargs))


    request = RequestFactory()


    def process_request(self, method, *args, **kwargs):
        if kwargs.pop("secure", False):
            kwargs["wsgi.url_scheme"] = "https"
        req = getattr(self.request, method.lower())(*args, **kwargs)
        return self.middleware.process_request(req)


    @override_settings(SECURE_FRAME_DENY=True)
    def test_frame_deny_on(self):
        """
        With SECURE_FRAME_DENY True, the middleware adds "x-frame-options:
        DENY" to the response.

        """
        self.assertEqual(self.process_response()["x-frame-options"], "DENY")


    @override_settings(SECURE_FRAME_DENY=True)
    def test_frame_deny_already_present(self):
        """
        The middleware will not override an "x-frame-options" header already
        present in the response.

        """
        response = self.process_response(headers={"x-frame-options": "ALLOW"})
        self.assertEqual(response["x-frame-options"], "ALLOW")


    @override_settings(SECURE_FRAME_DENY=False)
    def test_frame_deny_off(self):
        """
        With SECURE_FRAME_DENY False, the middleware does not add an
        "x-frame-options" header to the response.

        """
        self.assertFalse("x-frame-options" in self.process_response())


    @override_settings(SECURE_STS_SECONDS=3600)
    def test_sts_on(self):
        """
        With SECURE_STS_SECONDS=3600, the middleware adds
        "strict-transport-security: max-age=3600" to the response.

        """
        self.assertEqual(
            self.process_response()["strict-transport-security"],
            "max-age=3600")


    @override_settings(SECURE_STS_SECONDS=3600)
    def test_sts_already_present(self):
        """
        The middleware will not override a "strict-transport-security" header
        already present in the response.

        """
        response = self.process_response(
            headers={"strict-transport-security": "max-age=7200"})
        self.assertEqual(response["strict-transport-security"], "max-age=7200")


    @override_settings(SECURE_STS_SECONDS=0)
    def test_sts_off(self):
        """
        With SECURE_STS_SECONDS of 0, the middleware does not add an
        "strict-transport-security" header to the response.

        """
        self.assertFalse("strict-transport-security" in self.process_response())


    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_ssl_redirect_on(self):
        """
        With SECURE_SSL_REDIRECT True, the middleware redirects any non-secure
        requests to the https:// version of the same URL.

        """
        ret = self.process_request("get", "/some/url")
        self.assertEqual(ret.status_code, 301)
        self.assertEqual(ret["Location"], "https://testserver/some/url")


    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_no_redirect_ssl(self):
        """
        The middleware does not redirect secure requests.

        """
        ret = self.process_request("get", "/some/url", secure=True)
        self.assertEqual(ret, None)


    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_ssl_redirect_off(self):
        """
        With SECURE_SSL_REDIRECT False, the middleware does no redirect.

        """
        ret = self.process_request("get", "/some/url")
        self.assertEqual(ret, None)
