from datetime import datetime
from inspect import currentframe, stack
from pathlib import PurePath

import paramiko

from helpers.sleeper import sleeper


def line_number() -> int:
    """Uses inspect module to fetch the line number from current frame.

    Returns:
        int:
        Line number of where this function is called.
    """
    return currentframe().f_back.f_lineno


def replicated(level: str = 'INFO') -> str:
    """Replicates the logging config to print colored statements accordingly.

    Args:
        level: Takes the log level as an argument.

    Returns:
        str:
        A well formatted prefix to be added before a print statement.
    """
    return f"{datetime.now().strftime('%b-%d-%Y %I:%M:%S %p')} - {level} - [{PurePath(__file__).stem}:" \
           f"{line_number()}] - {stack()[1].function} - "


def run_interactive_ssh(hostname: str, pem_file: str, commands: dict, username: str = "ubuntu") -> bool:
    """Authenticates remote server using a ``*.pem`` file and runs interactive ssh commands using ``paramiko``.

    Args:
        hostname: Hostname of the server to connect to.
        pem_file: Takes the .pem filename to authenticate.
        commands: Takes a dictionary of commands as keys and the post command idle time as the values.
        username: Takes the username of the server to authenticate.

    Returns:
        bool:
        Returns a boolean flag if all commands were successful.
    """
    pem_key = paramiko.RSAKey.from_private_key_file(filename=pem_file)
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=hostname, username=username, pkey=pem_key)

    for command in commands:
        print(f"\033[32m{replicated(level='INFO')}Executing `{command}`\033[00m")
        stdin, stdout, stderr = ssh_client.exec_command(command)
        if output := stdout.read().decode('utf-8').strip():
            print(f"\033[32m{replicated(level='INFO')}{output}\033[00m")
        if error := stderr.read().decode("utf-8").strip():
            if error.startswith('debconf:'):
                print(f"\033[2;33m{replicated(level='WARNING')}{error}\033[00m")
            else:
                print(f"\033[31m{replicated(level='ERROR')}{error}\033[00m")
                return False
        sleeper(sleep_time=commands[command])
    ssh_client.close()
    return True
