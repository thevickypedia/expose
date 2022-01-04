from paramiko import AutoAddPolicy, RSAKey, SSHClient
from scp import SCPClient

from expose.helpers.auxiliary import prefix, sleeper


class ServerConfig:
    """Initiates ``ServerConfig`` object to create an SSH session.

    >>> ServerConfig

    """

    def __init__(self, hostname: str, pem_file: str, username: str = "ubuntu"):
        """Instantiates the session using RSAKey/.pem file.

        Args:
            hostname: Hostname of the server to connect to.
            pem_file: Takes the .pem filename to authenticate.
            username: Takes the username of the server to authenticate.
        """
        pem_key = RSAKey.from_private_key_file(filename=pem_file)
        self.ssh_client = SSHClient()
        self.ssh_client.load_system_host_keys()
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        self.ssh_client.connect(hostname=hostname, username=username, pkey=pem_key)

    def run_interactive_ssh(self, commands: dict) -> bool:
        """Authenticates remote server using a ``*.pem`` file and runs interactive ssh commands using ``paramiko``.

        Args:
            commands: Takes a dictionary of commands as keys and the post command idle time as the values.

        Returns:
            bool:
            Returns a boolean flag if all commands were successful.
        """
        for command in commands:
            print(f"\033[32m{prefix(level='INFO')}Executing `{command}`\033[00m")
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            if output := stdout.read().decode('utf-8').strip():
                print(f"\033[32m{prefix(level='INFO')}{output}\033[00m")
            if error := stderr.read().decode("utf-8").strip():
                if error.startswith('debconf:'):
                    print(f"\033[2;33m{prefix(level='WARNING')}{error}\033[00m")
                else:
                    print(f"\033[31m{prefix(level='ERROR')}{error}\033[00m")
                    return False
            sleeper(sleep_time=commands[command])
        self.ssh_client.close()
        return True

    def server_copy(self, files: list):
        """Copy files from local to the connected server.

        Args:
            files: List of files that has to be copied.
        """
        with SCPClient(self.ssh_client.get_transport()) as scp:
            scp.put(files=files)
