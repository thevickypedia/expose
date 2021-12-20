import paramiko

from helpers.sleeper import sleeper


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
        print(f"\033[32mExecuting `{command}`\033[00m")
        stdin, stdout, stderr = ssh_client.exec_command(command)
        print(f"\033[32m{stdout.read().decode('utf-8')}\033[00m")
        if error := stderr.read().decode("utf-8").strip():
            print(f"\033[31m{error}\033[00m")
            return False
        sleeper(sleep_time=commands[command])
    ssh_client.close()
    return True
