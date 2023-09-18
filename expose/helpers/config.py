import os
import pathlib
import sys


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
        self.aws_region_name: str = os.environ.get('AWS_REGION_NAME', os.environ.get('aws_region_name', 'us-east-2'))
        self.email_address: str = os.environ.get('EMAIL_ADDRESS', os.environ.get('email_address'))
        self.organization: str = os.environ.get('ORGANIZATION', os.environ.get('organization'))


class Settings:
    """Wrapper for AWS settings.

    >>> Settings

    """

    if sys.stdin.isatty():
        interactive: bool = True
    else:
        interactive: bool = False
    ssh_home: str = "/home/ubuntu"
    current_dir: os.PathLike = os.getcwd()
    key_pair_name: str = "expose_localhost"
    security_group_name: str = "Expose Localhost"
    key_pair_file: os.PathLike = os.path.join(current_dir, f"{key_pair_name}.pem")
    server_info: os.PathLike = os.path.join(current_dir, "server_info.json")
    configuration: os.PathLike = os.path.join(pathlib.Path(__file__).parent.parent, 'configuration')

    # Don't add path names because the same class variable will be used to perform server copy inside SSH
    cert_file: os.PathLike = "public.pem"
    key_file: os.PathLike = "private.pem"


settings = Settings()
