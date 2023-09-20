import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from expose.helpers.config import settings

DATETIME_FORMAT = '%b-%d-%Y %I:%M:%S %p'

try:
    IP_INFO = json.load(urlopen('http://ipinfo.io/json')) or json.load(urlopen('http://ip.jsontest.com'))
except (json.JSONDecodeError, URLError, HTTPError):
    IP_INFO = {}


def time_converter(seconds: float) -> str:
    """Modifies seconds to appropriate days/hours/minutes/seconds.

    Args:
        seconds: Takes number of seconds as argument.

    Returns:
        str:
        Seconds converted to days or hours or minutes or seconds.
    """
    days = round(seconds // 86400)
    seconds = round(seconds % (24 * 3600))
    hours = round(seconds // 3600)
    seconds %= 3600
    minutes = round(seconds // 60)
    seconds %= 60
    if days:
        return f'{days} days, {hours} hours, {minutes} minutes, and {seconds} seconds'
    elif hours:
        return f'{hours} hours, {minutes} minutes, and {seconds} seconds'
    elif minutes:
        return f'{minutes} minutes, and {seconds} seconds'
    elif seconds:
        return f'{seconds} seconds'


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
