import os

import dotenv

dotenv.load_dotenv(dotenv_path='.env')


class EnvConfig(dict):
    """Wrapper to load env variables.

    >>> EnvConfig

    """

    port: int = os.environ.get('PORT') or os.environ.get('port')
    image_id: str = os.environ.get('AMI_ID') or os.environ.get('ami_id')
    domain_name: str = os.environ.get('DOMAIN') or os.environ.get('domain')
    subdomain: str = os.environ.get('SUBDOMAIN') or os.environ.get('subdomain')
    aws_access_key: str = os.environ.get('ACCESS_KEY') or os.environ.get('access_key')
    aws_secret_key: str = os.environ.get('SECRET_KEY') or os.environ.get('secret_key')
    aws_region_name: str = os.environ.get('REGION_NAME') or os.environ.get('region_name') or 'us-west-2'
    email_address: str = os.environ.get('EMAIL_ADDRESS') or os.environ.get('email_address')
    organization: str = os.environ.get('ORGANIZATION') or os.environ.get('organization')


env = EnvConfig()


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
