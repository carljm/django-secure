from django.conf import settings



def check_session_cookie_secure():
    ret = set()
    if not settings.SESSION_COOKIE_SECURE:
        if _session_app():
            ret.add("SESSION_COOKIE_NOT_SECURE_APP_INSTALLED")
        if _session_middleware():
            ret.add("SESSION_COOKIE_NOT_SECURE_MIDDLEWARE")
        if len(ret) > 1:
            ret = set(["SESSION_COOKIE_NOT_SECURE"])
    return ret



def check_session_cookie_httponly():
    ret = set()
    if not settings.SESSION_COOKIE_HTTPONLY:
        if _session_app():
            ret.add("SESSION_COOKIE_NOT_HTTPONLY_APP_INSTALLED")
        if _session_middleware():
            ret.add("SESSION_COOKIE_NOT_HTTPONLY_MIDDLEWARE")
        if len(ret) > 1:
            ret = set(["SESSION_COOKIE_NOT_HTTPONLY"])
    return ret



def _session_middleware():
    return ("django.contrib.sessions.middleware.SessionMiddleware" in
            settings.MIDDLEWARE_CLASSES)



def _session_app():
    return ("django.contrib.sessions" in settings.INSTALLED_APPS)
