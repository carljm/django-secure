from django.utils.functional import wraps


def frame_deny_exempt(view):
    @wraps(view)
    def inner(*args, **kwargs):
        response = view(*args, **kwargs)
        response._frame_deny_exempt = True
        return response

    return inner
