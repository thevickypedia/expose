import os
import pathlib


class EnvConfig:
    """Wrapper to load env variables.

    >>> EnvConfig

    """

    def __init__(self):
        """Load all env vars."""
        # todo: Use pydantic to load env vars
        self.port: str = os.environ.get('PORT', os.environ.get('port'))
        self.image_id: str = os.environ.get('IMAGE_ID', os.environ.get('image_id'))
        self.domain: str = os.environ.get('DOMAIN', os.environ.get('domain'))
        self.subdomain: str = os.environ.get('SUBDOMAIN', os.environ.get('subdomain'))
        self.aws_access_key: str = os.environ.get('AWS_ACCESS_KEY', os.environ.get('aws_access_key'))
        self.aws_secret_key: str = os.environ.get('AWS_SECRET_KEY', os.environ.get('aws_secret_key'))
        self.aws_region_name: str = os.environ.get('AWS_REGION_NAME', os.environ.get('aws_region_name', 'us-west-2'))
        self.email_address: str = os.environ.get('EMAIL_ADDRESS', os.environ.get('email_address'))
        self.organization: str = os.environ.get('ORGANIZATION', os.environ.get('organization'))


class WaitTimes:
    """Wrapper for different wait times.

    >>> WaitTimes

    """

    # todo: Use built-in ec2 waiters instead of hard coded sleep
    instance_warmup: int = 30
    instance_warmup_refresh: int = 5
    ssh_warmup: int = 15
    unhook_sg: int = 90
    unhook_sg_refresh: int = 20


wait = WaitTimes()


class FileIO:
    """Wrapper for file objects.

    >>> FileIO

    """

    ssh_home: str = "/home/ubuntu"
    current_dir: os.PathLike = os.getcwd()
    tunnel_raw: str = "expose_localhost"
    tunnel: os.PathLike = os.path.join(current_dir, f"{tunnel_raw}.pem")
    server_info: os.PathLike = os.path.join(current_dir, "server_info.json")
    configuration: os.PathLike = os.path.join(pathlib.Path(__file__).parent.parent, 'configuration')

    # Don't add path names because the same class variable will be used to perform server copy inside SSH
    cert_file: os.PathLike = "public.pem"
    key_file: os.PathLike = "private.pem"


fileio = FileIO()
