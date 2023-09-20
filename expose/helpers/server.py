import logging
import time
from select import select
from socket import socket
from threading import Thread
from typing import List, Tuple, Union

import requests
from paramiko import AutoAddPolicy, RSAKey, SSHClient
from paramiko.channel import Channel
from paramiko.transport import Transport

from expose.helpers.auxiliary import flush_screen, write_screen
from expose.helpers.config import env, settings


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


def print_warning() -> None:
    """Prints a message on screen to run an app or api on the specific port."""
    write_screen(f'Run an application on the port {env.port} to start tunneling.')
    time.sleep(5)
    flush_screen()


class Server:
    """Initiates ``Server`` object to create an SSH session to configure the server and intiate the tunneling.

    >>> Server

    **Reverse SSH Port Forwarding**

    Specifies that the given port on the remote server host is to be forwarded to the given host and port on the
    local side. So, instead of your machine doing a simple SSH, the server does an SSH and through the port
    forwarding makes sure that you can SSH back to the server machine.
    """

    def __init__(self,
                 hostname: str,
                 pem_file: str,
                 logger: logging.Logger,
                 username: str = "ubuntu",
                 timeout: int = 30):
        """Instantiates the session using RSAKey generated from a ``***.pem`` file.

        Args:
            hostname: Hostname of the server to connect to.
            pem_file: Takes the .pem filename to authenticate.
            username: Takes the username of the server to authenticate.
            timeout: Connection timeout for SSH server.
        """
        pem_key = RSAKey.from_private_key_file(filename=pem_file)
        self.ssh_client = SSHClient()
        self.ssh_client.load_system_host_keys()
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        self.ssh_client.connect(hostname=hostname, username=username, pkey=pem_key, timeout=timeout)
        self.logger = logger

    def run_interactive_ssh(self, commands: Tuple[str, str, str, str, str]) -> bool:
        """Authenticates remote server using a ``*.pem`` file and runs interactive ssh commands using ``paramiko``.

        Args:
            commands: List of commands to be executed.

        Returns:
            bool:
            Returns a boolean flag if all commands were successful.
        """
        for command in commands:
            self.logger.info("Executing '%s'", command)
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            if output := stdout.read().decode('utf-8').strip():
                self.logger.info(output)
            if error := stderr.read().decode("utf-8").strip():
                if error.startswith('debconf:') or 'could not get lock' in error.lower():
                    self.logger.warning(error)
                else:
                    self.logger.error(error)
                    self.ssh_client.close()
                    return False
            time.sleep(2)
        return True

    def server_write(self, data: dict) -> None:
        """Writes data into files.

        Args:
            data: Takes a dictionary of key-value pair filename and content.
        """
        ftp = self.ssh_client.open_sftp()
        for filename, content in data.items():
            if not filename.startswith("/"):
                filename = f"{settings.ssh_home}/{filename}"
            file = ftp.file(filename=filename, mode='w')
            file.write(content)
            file.flush()
        ftp.close()

    def _handler(self, channel: Channel, port: int) -> None:
        """Creates a socket and handles TCP IO on the channel created.

        Args:
            channel: Channel for Transport.
            port: Port number on which the socket should connect.
        """
        socket_ = socket()
        try:
            socket_.connect(('localhost', port))
        except Exception as error:
            self.logger.error("Forwarding request to localhost:%d failed: %s", port, error)
            self.ssh_client.close()
            return

        self.logger.info("Connection open %s -> %s -> %s",
                         join(channel.origin_addr), join(channel.getpeername()), join(channel.origin_addr))
        while True:
            read, write, execute = select([socket_, channel], [], [])
            if socket_ in read:
                if data := socket_.recv(1024):
                    channel.send(data)
                else:
                    break
            if channel in read:
                if not (data := channel.recv(1024)):
                    break
                socket_.send(data)
        channel.close()
        socket_.close()
        self.logger.info("Connection closed from %s", join(channel.origin_addr))

    def stop_tunnel(self, transport: Transport, threads: List[Thread]) -> None:
        """Stops port forwarding.

        Args:
            transport: Transport object that creates the channel
            threads: Daemon threads handling connections.
        """
        if host_keys := self.ssh_client.get_host_keys().keys():
            self.logger.info("Closing SSH connection on %s", host_keys[0])
        else:
            self.logger.info("Closing SSH connection on %s", join(transport.getpeername()))
        transport.cancel_port_forward(address="localhost", port=8080)
        self.ssh_client.close()
        self.logger.info("Daemons launched: %d", len(threads))
        for thread in threads:
            self.logger.debug("Awaiting daemon service: %s", thread.ident or thread.native_id)
            thread.join(timeout=0.5)

    def initiate_tunnel(self, protocol: str) -> None:
        """Initiates port forwarding using ``Transport`` which creates a channel."""
        while True:
            try:
                requests.get(f'http://localhost:{env.port}')
                self.logger.info('Application is running on port: %d', env.port)
                flush_screen()
                break
            except requests.exceptions.RequestException:
                try:
                    print_warning()
                except KeyboardInterrupt:
                    return
        self.logger.info("Awaiting connection...")
        transport: Transport = self.ssh_client.get_transport()
        transport.request_port_forward(address="localhost", port=8080)
        threads: List[Thread] = []
        try:
            while True:
                if not (channel := transport.accept(timeout=1000)):
                    continue
                thread = Thread(target=self._handler, args=(channel, env.port), daemon=True)
                thread.start()
                self.logger.debug("Launching daemon service: %s", thread.ident or thread.native_id)
                threads.append(thread)
        except KeyboardInterrupt:
            self.logger.info("Tunneling interrupted")
        finally:
            self.stop_tunnel(transport, threads)
