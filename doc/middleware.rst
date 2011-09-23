SecurityMiddleware
==================

The ``djangosecure.middleware.SecurityMiddleware`` performs three different
tasks for you. Each one can be independently enabled or disabled with a
setting.

.. contents:: :local:

.. _x-frame-options:

X-Frame-Options: DENY
---------------------

`Clickjacking`_ attacks use layered frames to mislead users into clicking on a
different link from the one they think they are clicking on. Fortunately, newer
browsers support an ``X-Frame-Options`` header that allows you to limit or
prevent the display of your pages within a frame. Valid options are "DENY" or
"SAMEORIGIN" - the former prevents all framing of your site, and the latter
allows only sites within the same domain to frame.

Unless you have a need for frames, your best bet is to set "X-Frame-Options:
DENY" -- and this is what ``SecurityMiddleware`` will do for all responses, if
the :ref:`SECURE_FRAME_DENY` setting is ``True``.

If you have a few pages that should be frame-able, you can set the
"X-Frame-Options" header on the response to "SAMEORIGIN" in the view;
``SecurityMiddleware`` will not override an already-present "X-Frame-Options"
header. If you don't want the "X-Frame-Options" header on this view's response
at all, decorate the view with the ``frame_deny_exempt`` decorator::

    from djangosecure.decorators import frame_deny_exempt
    
    @frame_deny_exempt
    def my_view(request):
        # ...

.. _Clickjacking: http://www.sectheory.com/clickjacking.htm

.. _http-strict-transport-security:

HTTP Strict Transport Security
------------------------------

For sites that should only be accessed over HTTPS, you can instruct newer
browsers to refuse to connect to your domain name via an insecure connection
(for a given period of time) by setting the `"Strict-Transport-Security"
header`_. This reduces your exposure to some SSL-stripping man-in-the-middle
(MITM) attacks.

``SecurityMiddleware`` will set this header for you on all HTTPS responses if
you set the :ref:`SECURE_HSTS_SECONDS` setting to a nonzero integer value.

.. warning::
    The HSTS policy applies to your entire domain, not just the URL of the
    response that you set the header on. Therefore, you should only use it if
    your entire domain is served via HTTPS only.

.. warning::
    Browsers properly respecting the HSTS header will refuse to allow users to
    bypass warnings and connect to a site with an expired, self-signed, or
    otherwise invalid SSL certificate. If you use HSTS, make sure your
    certificates are in good shape and stay that way!

.. note::
    If you are deployed behind a load-balancer or reverse-proxy server, and the
    Strict-Transport-Security header is not being added to your responses, it
    may be because Django doesn't realize when it's on a secure connection; you
    may need to set the :ref:`SECURE_PROXY_SSL_HEADER` setting.

.. _"Strict-Transport-Security" header: http://en.wikipedia.org/wiki/Strict_Transport_Security

.. _x-content-type-options:

X-Content-Type-Options: nosniff
-------------------------------

Some browsers will try to guess the content types of the assets that they
fetch, overriding the ``Content-Type`` header. While this can help display
sites with improperly configured servers, it can also pose a security
risk.

If your site serves user-uploaded files, a malicious user could upload a
specially-crafted file that would be interpreted as HTML or Javascript by
the browser when you expected it to be something harmless.

To learn more about this header and how the browser treats it, you can
read about it on the `IE Security Blog`_.

To prevent the browser from guessing the content type, and force it to
always use the type provided in the ``Content-Type`` header, you can pass
the ``X-Content-Type-Options: nosniff`` header.  ``SecurityMiddleware`` will
do this for all responses if the :ref:`SECURE_CONTENT_TYPE_NOSNIFF` setting
is ``True``.

.. _IE Security Blog: http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx

.. _ssl-redirect:

SSL Redirect
------------

If your site offers both HTTP and HTTPS connections, most users will end up
with an unsecured connection by default. For best security, you should redirect
all HTTP connections to HTTPS.

If you set the :ref:`SECURE_SSL_REDIRECT` setting to True,
``SecurityMiddleware`` will permanently (HTTP 301) redirect all HTTP
connections to HTTPS.

.. note::

    For performance reasons, it's preferable to do these redirects outside of
    Django, in a front-end loadbalancer or reverse-proxy server such as
    `nginx`_. In some deployment situations this isn't an option -
    :ref:`SECURE_SSL_REDIRECT` is intended for those cases.

If the :ref:`SECURE_SSL_HOST` setting has a value, all redirects will be sent
to that host instead of the originally-requested host.

If there are a few pages on your site that should be available over HTTP, and
not redirected to HTTPS, you can list regular expressions to match those URLs
in the :ref:`SECURE_REDIRECT_EXEMPT` setting.

.. note::
    If you are deployed behind a load-balancer or reverse-proxy server, and
    Django can't seem to tell when a request actually is already secure, you
    may need to set the :ref:`SECURE_PROXY_SSL_HEADER` setting.

.. _nginx: http://nginx.org
