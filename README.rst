=============
django-secure
=============

Helping you remember to do the stupid little things to improve your Django
site's security.

Inspired by Mozilla's `Secure Coding Guidelines`_, and intended for sites that
are entirely or mostly served over SSL (which should include anything with
user logins).

.. _Secure Coding Guidelines: https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines

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

* Set the ``SECURE_SSL_REDIRECT`` setting to ``True`` if all non-SSL requests
  should be permanently redirected to SSL.

* Set the ``SECURE_HSTS_SECONDS`` setting to an integer number of seconds, if
  you want to use `HTTP Strict Transport Security`_.

* Set the ``SECURE_FRAME_DENY`` setting to ``True``, if you want to prevent
  framing of your pages and protect them from `clickjacking`_.

* Set the ``SECURE_CONTENT_TYPE_NOSNIFF`` setting to ``True``, if you want to prevent
  the browser from guessing asset content types.

* Set the ``SECURE_XSS_FILTER`` setting to ``True``, if you want to enable
  the browser's XSS filtering protections.

* Set ``SESSION_COOKIE_SECURE`` and ``SESSION_COOKIE_HTTPONLY`` to ``True`` if
  you are using ``django.contrib.sessions``. These settings are not part of
  ``django-secure``, but they should be used if running a secure site, and the
  ``checksecure`` management command will check their values.

* Run ``python manage.py checksecure`` to verify that your settings are
  properly configured for serving a secure SSL site.

.. _HTTP Strict Transport Security: http://en.wikipedia.org/wiki/Strict_Transport_Security

.. _clickjacking: http://www.sectheory.com/clickjacking.htm

.. warning::
    If ``checksecure`` gives you the all-clear, all it means is that you're now
    taking advantage of a tiny selection of simple and easy security
    wins. That's great, but it doesn't mean your site or your codebase is
    secure: only a competent security audit can tell you that.

.. end-here

Documentation
-------------

See the `full documentation`_ for more details.

.. _full documentation: http://django-secure.readthedocs.org
