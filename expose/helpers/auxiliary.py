import json
import sys
from time import sleep
from urllib.request import urlopen


def sleeper(sleep_time: int) -> None:
    """Sleeps for a particular duration and prints the remaining time in console output.

    Args:
        sleep_time: Takes the time script has to sleep, as an argument.
    """
    sleep(1)
    for i in range(sleep_time):
        sys.stdout.write(f'\rRemaining: {sleep_time - i:0{len(str(sleep_time))}}s')
        sleep(1)
    sys.stdout.write('\r')


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


def get_public_ip() -> str:
    """Gets the public IP address from ``ipinfo.io`` or ``ip.jsontest.com``.

    Returns:
        str:
        Returns the public IP address.
    """
    public_ip = json.load(urlopen('https://ipinfo.io/json')).get('ip') or \
        json.loads(urlopen('http://ip.jsontest.com').read()).get('ip')
    return public_ip
