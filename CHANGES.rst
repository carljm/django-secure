CHANGES
=======

1.0.2 (2020.03.31)
-------------------

* This project was merged into Django 1.8 and its features are now part of core
  Django. Thus it is unmaintained and you should not use it.

1.0.1 (2014.10.23)
------------------

* Hide django-secure tests from pre-1.6 Django test runners, to avoid breaking
  project tests.


1.0 (2013.04.17)
----------------

* BACKWARDS INCOMPATIBLE: Dropped tested support for Python 2.5, Django 1.2,
  and Django 1.3.

* Added support and testing for Python 3 (though all non-test code worked fine
  under Python 3 previously.)


0.1.3 (2013.04.17)
------------------

* Added check for ``SECRET_KEY``. Thanks Ram Rachum.

0.1.2 (2012.04.13)
------------------

* Added the ``SECURE_HSTS_INCLUDE_SUBDOMAINS`` setting. Thanks Paul McMillan
  for the report and Donald Stufft for the patch. Fixes #13.

* Added the ``X-XSS-Protection: 1; mode=block`` header. Thanks Johannas Heller.


0.1.1 (2011.11.23)
------------------

* Added the ``X-Content-Type-Options: nosniff`` header. Thanks Johannas Heller.

* ``SECURE_PROXY_SSL_HEADER`` setting now patches ``request.is_secure()`` so it
  respects proxied SSL, to avoid redirects to http that should be to https.


0.1.0 (2011.05.29)
------------------

* Initial release.

