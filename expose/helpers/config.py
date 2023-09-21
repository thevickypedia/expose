import getpass
import os
import pathlib
import re
import sys
from typing import Union

from pydantic import (BaseModel, DirectoryPath, EmailStr, Field, FilePath,
                      field_validator)
from pydantic_settings import BaseSettings


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
    domain: Union[str, None] = None  # todo: change this to hosted zone name
    subdomain: Union[str, None] = None  # todo: change this to A record
    aws_access_key: Union[str, None] = None
    aws_secret_key: Union[str, None] = None
    email_address: EmailStr = f"{getpass.getuser()}@expose-localhost.com"
    organization: Union[str, None] = None

    # noinspection PyMethodParameters
    @field_validator('domain')
    def domain_validator(cls, v: str) -> Union[str, None]:
        """Custom validation for 'domain' field."""
        if not v:
            return None
        if re.match(pattern=r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", string=v):
            if len(v.split('.')) == 2:
                return v
            raise ValueError("Field 'domain' should ONLY be a FQDN, 'subdomain' should be set separately")
        raise ValueError("Field 'domain' should be a fully qualified domain name")

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
    if any((env.domain, env.subdomain)):
        assert all((env.domain, env.subdomain)), "'subdomain' and 'domain' must co-exist"
        entrypoint: str = f'{env.subdomain}.{env.domain}'


settings = Settings()
