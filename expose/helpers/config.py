import os


class EnvConfig:
    """Wrapper to load env variables.

    >>> EnvConfig

    """

    def __init__(self):
        """Load all env vars."""
        self.port: str = os.environ.get('PORT') or os.environ.get('port')
        self.image_id: str = os.environ.get('IMAGE_ID') or os.environ.get('image_id')
        self.domain: str = os.environ.get('DOMAIN') or os.environ.get('domain')
        self.subdomain: str = os.environ.get('SUBDOMAIN') or os.environ.get('subdomain')
        self.aws_access_key: str = os.environ.get('AWS_ACCESS_KEY') or os.environ.get('aws_access_key')
        self.aws_secret_key: str = os.environ.get('AWS_SECRET_KEY') or os.environ.get('aws_secret_key')
        self.aws_region_name: str = os.environ.get('AWS_REGION_NAME') or os.environ.get('aws_region_name', 'us-west-2')
        self.email_address: str = os.environ.get('EMAIL_ADDRESS') or os.environ.get('email_address')
        self.organization: str = os.environ.get('ORGANIZATION') or os.environ.get('organization')


class WaitTimes:
    """Wrapper for different wait times.

    >>> WaitTimes

    """

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

    ssh_home: os.PathLike = os.path.join(os.path.expanduser('~'), ".ssh")
    current_dir: os.PathLike = os.getcwd()
    tunnel_raw: str = "Tunnel"
    tunnel: os.PathLike = os.path.join(current_dir, f"{tunnel_raw}.pem")
    server_info: os.PathLike = os.path.join(current_dir, "server_info.json")


fileio = FileIO()
