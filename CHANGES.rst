CHANGES
=======

tip (unreleased)
----------------

* Added the ``X-XSS-Protection: 1; mode=block`` header. Thanks Johannas Heller.

* Added the ``X-Content-Type-Options: nosniff`` header. Thanks Johannas Heller.

* ``SECURE_PROXY_SSL_HEADER`` setting now patches ``request.is_secure()`` so it
  respects proxied SSL, to avoid redirects to http that should be to https.


0.1.0 (2011.05.29)
------------------

* Initial release.

