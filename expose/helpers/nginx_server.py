from select import select
from socket import socket
from threading import Thread
from typing import Union

from paramiko import AutoAddPolicy, RSAKey, SSHClient
from paramiko.channel import Channel
from paramiko.transport import Transport
from scp import SCPClient

from expose.helpers.auxiliary import prefix, sleeper


def join(value: Union[tuple, list, str], separator: str = ':') -> str:
    """Uses ``.join`` to squash a list or tuple using a separator.

    Args:
        value: Value to be squashed.
        separator: Separator to be used to squash.

    Returns:
        str:
        A squashed string.
    """
    return separator.join(map(str, value))


class ServerConfig:
    """Initiates ``ServerConfig`` object to create an SSH session to configure the server and intiate the tunneling.

    >>> ServerConfig

    **Reverse SSH Port Forwarding**

    Specifies that the given port on the remote server host is to be forwarded to the given host and port on the
    local side. So, instead of your machine doing a simple SSH, the server does an SSH and through the port
    forwarding makes sure that you can SSH back to the server machine.
    """

    def __init__(self, hostname: str, pem_file: str, username: str = "ubuntu"):
        """Instantiates the session using RSAKey generated from a ``***.pem`` file.

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
                if error.startswith('debconf:') or 'could not get lock' in error.lower():
                    print(f"\033[2;33m{prefix(level='WARNING')}{error}\033[00m")
                else:
                    print(f"\033[31m{prefix(level='ERROR')}{error}\033[00m")
                    self.ssh_client.close()
                    return False
            sleeper(sleep_time=commands[command])
        return True

    def server_copy(self, files: list, retry: bool = False) -> bool:
        """Copy files from local to the connected server.

        Args:
            files: List of files that has to be copied.
            retry: Retry to copy the file.

        Returns:
            bool:
            A boolean flag to indicate whether files were copied successfully.
        """
        with SCPClient(self.ssh_client.get_transport()) as scp:
            scp.put(files=files)
        sftp = self.ssh_client.open_sftp()
        for file in files:
            try:
                sftp.stat(file.split('/')[-1])
            except IOError:
                if not retry:
                    print(f"\033[2;33m{prefix(level='WARNING')}{file} was not copied successfully. Retrying..\033[00m")
                    self.server_copy(files=[file], retry=True)
                print(f"\033[31m{prefix(level='ERROR')}{file} was not copied successfully.\033[00m")
                return False
        return True

    def handler(self, channel: Channel, port: int) -> None:
        """Creates a socket and handles TCP IO on the channel created.

        Args:
            channel: Channel for Transport.
            port: Port number on which the socket should connect.
        """
        socket_ = socket()
        try:
            socket_.connect(('localhost', port))
        except Exception as error:
            print(f"\033[31m{prefix(level='ERROR')}Forwarding request to localhost:{str(port)} failed: {error}\033[00m")
            self.ssh_client.close()
            return

        print(f"\033[32m{prefix(level='INFO')}Connection open "
              f"{join(channel.origin_addr)} → {join(channel.getpeername())} → localhost:{port}\033[00m")
        while True:
            read, write, execute = select([socket_, channel], [], [])
            if socket_ in read:
                if not (data := socket_.recv(1024)):
                    break
                channel.send(data)
            if channel in read:
                if not (data := channel.recv(1024)):
                    break
                socket_.send(data)
        channel.close()
        socket_.close()
        print(f"\033[2;33m{prefix(level='INFO')}Connection closed from {join(channel.origin_addr)}\033[00m")

    def initiate_tunnel(self, port: int) -> None:
        """Initiates port forwarding using ``Transport`` which creates a channel.

        Args:
            port: Port number on which the channel has to be
        """
        print(f"\033[32m{prefix(level='INFO')}Awaiting connection...\033[00m")
        transport: Transport = self.ssh_client.get_transport()
        transport.request_port_forward(address="localhost", port=8080)
        try:
            while True:
                if not (channel := transport.accept(timeout=1000)):
                    continue
                Thread(target=self.handler, args=[channel, port], daemon=True).start()
        except KeyboardInterrupt:
            print(f"\033[2;33m{prefix(level='WARNING')}Tunneling interrupted\033[00m")
        print(f"\033[2;33m{prefix(level='WARNING')}Stopping reverse tunneling on "
              f"{join(transport.getpeername())}\033[00m")
        transport.cancel_port_forward(address="localhost", port=8080)
        print(f"\033[2;33m{prefix(level='WARNING')}Closing SSH connection to "
              f"{self.ssh_client.get_host_keys().keys()[0]}\033[00m")
        self.ssh_client.close()
