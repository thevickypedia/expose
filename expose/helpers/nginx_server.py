from datetime import datetime
from inspect import currentframe, getframeinfo, getouterframes, stack

from paramiko import AutoAddPolicy, RSAKey, SSHClient

from expose.helpers.auxiliary import sleeper

DATETIME_FORMAT = '%b-%d-%Y %I:%M:%S %p'


def prefix(level: str = 'DEBUG') -> str:
    """Replicates the logging config to print colored statements accordingly.

    Args:
        level: Takes the log level as an argument.

    Returns:
        str:
        A well formatted prefix to be added before a print statement.
    """
    calling_file = getouterframes(currentframe(), 2)[1][1].split('/')[-1].rstrip('.py')
    return f"{datetime.now().strftime(DATETIME_FORMAT)} - {level} - [{calling_file}:" \
           f"{getframeinfo(stack()[1][0]).lineno}] - {stack()[1].function} - "


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
    pem_key = RSAKey.from_private_key_file(filename=pem_file)
    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    ssh_client.connect(hostname=hostname, username=username, pkey=pem_key)

    for command in commands:
        print(f"\033[32m{prefix(level='INFO')}Executing `{command}`\033[00m")
        stdin, stdout, stderr = ssh_client.exec_command(command)
        if output := stdout.read().decode('utf-8').strip():
            print(f"\033[32m{prefix(level='INFO')}{output}\033[00m")
        if error := stderr.read().decode("utf-8").strip():
            if error.startswith('debconf:'):
                print(f"\033[2;33m{prefix(level='WARNING')}{error}\033[00m")
            else:
                print(f"\033[31m{prefix(level='ERROR')}{error}\033[00m")
                return False
        sleeper(sleep_time=commands[command])
    ssh_client.close()
    return True
