=============
django-secure
=============

Utilities for running a secure Django site (where all URLs in the site should
be accessed over an HTTPS connection).

Quickstart
==========

Dependencies
------------

Tested with `Django`_ 1.2 through trunk, and `Python`_ 2.5 through 2.7. Quite
likely works with older versions of both, though; it's not very complicated.

.. _Django: http://www.djangoproject.com/
.. _Python: http://www.python.org/

Installation
------------

Install from PyPI with ``pip``::

    pip install django-secure

or get the `in-development version`_::

    pip install django-secure==dev

.. _in-development version: https://github.com/carljm/django-secure/tarball/master#egg=django_secure-dev

Usage
-----

* Add ``"djangosecure"`` to your ``INSTALLED_APPS`` setting.

* Add ``"djangosecure.middleware.SecurityMiddleware"`` to your
  ``MIDDLEWARE_CLASSES`` setting (where depends on your other middlewares, but
  near the beginning of the list is probably a good choice).

* Set the ``SECURE_SSL_REDIRECT`` setting to True if all non-SSL requests
  should be permanently redirected to SSL.

* Set the ``SECURE_STS_SECONDS`` setting to an integer number of seconds, if
  you want to use `Strict Transport Security`_.

* Set ``SESSION_COOKIE_SECURE`` and ``SESSION_COOKIE_HTTPONLY`` to ``True`` if
  you are using ``django.contrib.sessions``. These settings are not part of
  ``django-secure``, but they should be used if running a secure site, and the
  ``checksecure`` management command will check their values.

* Run ``python manage.py checksecure`` to verify that your settings are
  properly configured for serving a secure SSL site.

.. _Strict Transport Security: http://en.wikipedia.org/wiki/Strict_Transport_Security

Documentation
-------------

See the `full documentation`_ for more details.

.. _full documentation: http://django-secure.readthedocs.org
