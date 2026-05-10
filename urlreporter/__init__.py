__version__ = "1.0.2"

APP_NAME = "Url Reporter"
AUTHOR_NAME = "Paolo Diomede"
AUTHOR_URL = "https://pdiomede.com"


def credit_line() -> str:
    return f"{APP_NAME} v{__version__} | Built by {AUTHOR_NAME}"
