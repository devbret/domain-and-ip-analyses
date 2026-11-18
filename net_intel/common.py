from .models import JSONLike

USER_AGENT = "net-intel/1.0"


def safe_call(fn, *args, **kwargs) -> JSONLike:
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        return f"{type(e).__name__}: {e}"
