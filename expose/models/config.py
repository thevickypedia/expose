import getpass
import os
import pathlib
import sys
from typing import Dict, Union

from pydantic import BaseModel, DirectoryPath, EmailStr, Field, FilePath
from pydantic_settings import BaseSettings


class AWSDefaults(BaseModel):
    """Default values for missing AWS configuration.

    >>> AWSDefaults

    """

    DEFAULT_AMI_NAME: str = "aerospike-ubuntu-20.04-20211114101915"

    IMAGE_MAP: Dict[str, str] = {
        "us-east-1": "ami-0eaca42ad8ff8647d",
        "us-east-2": "ami-0971e839208a0d58a",
        "us-west-1": "ami-0005fe7be6ce06e3c",
        "us-west-2": "ami-06e20d17437157772"
    }


aws = AWSDefaults()


class EnvConfig(BaseSettings):
    """Env configuration.

    >>> EnvConfig

    References:
        https://docs.pydantic.dev/2.3/migration/#required-optional-and-nullable-fields
    """

    port: int

    aws_region_name: str = "us-east-2"

    key_pair: str = "expose_localhost"
    security_group: str = "Expose Localhost"

    key_file: str = Field("private.pem", pattern=r".+\.pem$")
    cert_file: str = Field("public.pem", pattern=r".+\.pem$")
    server_info: str = Field("server_info.json", pattern=r".+\.json$")

    image_id: Union[str, None] = None
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
    entrypoint: str = None
    if any((env.hosted_zone, env.subdomain)):
        assert all((env.hosted_zone, env.subdomain)), "'subdomain' and 'hosted_zone' must co-exist"
        entrypoint: str = f'{env.subdomain}.{env.hosted_zone}'


settings = Settings()
