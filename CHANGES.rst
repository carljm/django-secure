CHANGES
=======

0.1.1 (2011.11.23)
------------------

* Added the ``X-Content-Type-Options: nosniff`` header. Thanks Johannas Heller.

* ``SECURE_PROXY_SSL_HEADER`` setting now patches ``request.is_secure()`` so it
  respects proxied SSL, to avoid redirects to http that should be to https.


0.1.0 (2011.05.29)
------------------

* Initial release.

