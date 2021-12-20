import sys
from time import sleep


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
