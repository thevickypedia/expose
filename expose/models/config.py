import getpass
import os
import pathlib
import sys
from typing import Dict, Union

from pydantic import (BaseModel, DirectoryPath, EmailStr, Field, FilePath,
                      HttpUrl)
from pydantic_settings import BaseSettings


class AMIBase(BaseModel):
    """Default values to fetch AMI image ID.

    >>> AMIBase

    """

    _BASE_URL: str = 'https://aws.amazon.com/marketplace/server/configuration?productId={productId}'
    _BASE_SSM: str = '/aws/service/marketplace/prod-{path}'

    # Published by 'Amazon Web Services' but only served via AMI name
    PRODUCT_PAGE: HttpUrl = _BASE_URL.format(productId='89c9b5d3-48a2-4098-813e-86b817274442')
    NAME: str = 'ubuntu-pro-server/images/hvm-ssd/ubuntu-focal-20.04-amd64-pro-server-20230815'
    ALIAS: str = _BASE_SSM.format(path='733j3j6jvf5s2/v20230815')
    PRODUCT_CODE: str = '85nyo8r8xh6zoav4dsao5to3m'

    # Published by 'Canonical Group Limited' but only served via AMI name
    S_PRODUCT_PAGE: HttpUrl = _BASE_URL.format(productId='e2e33685-9a6f-4cb6-ae4e-eb075484baed')
    S_NAME: str = 'ubuntu/images/hvm-ssd/ubuntu-lunar-23.04-amd64-server-20230918-e2e33685-9a6f-4cb6-ae4e-eb075484baed'
    S_ALIAS: str = _BASE_SSM.format(path='5k5cl7gpbkr26/ubuntu-23.04-20230918')
    S_PRODUCT_CODE: str = 'dfk90rdx2y6rx3801br52xh4d'


ami_base = AMIBase()


class EnvConfig(BaseSettings):
    """Env configuration.

    >>> EnvConfig

    References:
        https://docs.pydantic.dev/2.3/migration/#required-optional-and-nullable-fields
    """

    port: int
    open_port: bool = False
    channel_timeout: int = Field(100, le=1_000, ge=1)

    image_id: Union[str, None] = Field(None, pattern="^ami-.*")
    instance_type: str = "t2.nano"
    aws_region_name: str = "us-east-2"

    key_pair: str = "expose_localhost"
    security_group: str = "Expose Localhost"

    key_file: str = Field("private.pem", pattern=r".+\.pem$")
    cert_file: str = Field("public.pem", pattern=r".+\.pem$")
    server_info: str = Field("server_info.json", pattern=r".+\.json$")

    hosted_zone: Union[str, None] = None
    subdomain: Union[str, None] = None
    aws_access_key: Union[str, None] = None
    aws_secret_key: Union[str, None] = None

    email_address: EmailStr = f"{getpass.getuser()}@expose-localhost.com"
    organization: Union[str, None] = None

    class Config:
        """Extra config for .env file and extra."""

        extra = "allow"
        env_file = os.environ.get('env_file', os.environ.get('ENV_FILE', '.env'))


env = EnvConfig()


class Settings(BaseModel):
    """Wrapper for AWS settings.

    >>> Settings

    """

    if sys.stdin.isatty():
        interactive: bool = True
    else:
        interactive: bool = False
    current_dir: DirectoryPath = os.getcwd()
    ssh_home: str = "/home/ubuntu"
    key_pair_file: FilePath = f"{env.key_pair}.pem"
    configuration: DirectoryPath = os.path.join(pathlib.Path(__file__).parent.parent, 'configuration')
    ami_deprecation: int = 30
    entrypoint: str = None
    if any((env.hosted_zone, env.subdomain)):
        assert all((env.hosted_zone, env.subdomain)), "'subdomain' and 'hosted_zone' must co-exist"
        entrypoint: str = f'{env.subdomain}.{env.hosted_zone}'
    nginx_config_commands: Dict[str, bool] = {
        "sudo apt-get update -y": True,
        "echo Y | sudo -S apt-get install nginx -y": True,
        f"sudo mv {ssh_home}/nginx.conf /etc/nginx/nginx.conf": True,
        f"sudo mv {ssh_home}/server.conf /etc/nginx/conf.d/server.conf": True,
        "sudo systemctl restart nginx": True,
        "sudo systemctl mask unattended-upgrades": False,  # avoid starting any upgrades
        "sudo systemctl stop unattended-upgrades": False,  # stop any upgrades in flight
        "sudo pkill --signal SIGKILL unattended-upgrades": False,  # kill processes that are running upgrades
        "sudo systemctl disable unattended-upgrades": False,  # disable any future unattended upgrades
        "sudo apt-get purge unattended-upgrades -y": False,  # purge the package
        "sudo systemctl unmask unattended-upgrades": False  # remove mask
    }


settings = Settings()
