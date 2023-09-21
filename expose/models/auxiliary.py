import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from expose.models.config import settings

try:
    IP_INFO = json.load(urlopen('http://ipinfo.io/json')) or json.load(urlopen('http://ip.jsontest.com'))
except (json.JSONDecodeError, URLError, HTTPError):
    IP_INFO = {}


def write_screen(text: Any) -> None:
    """Write text on screen that can be cleared later.

    Args:
        text: Text to be written.
    """
    sys.stdout.write(f"\r{text}")


def flush_screen() -> None:
    """Flushes the screen output.

    See Also:
        Writes new set of empty strings for the size of the terminal if ran using one.
    """
    if settings.interactive:
        sys.stdout.write(f"\r{' '.join(['' for _ in range(os.get_terminal_size().columns)])}")
    else:
        sys.stdout.write("\r")
