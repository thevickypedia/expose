import os
from typing import NoReturn, Union

import dotenv

from expose.helpers import config  # noqa: F401
from expose.main import Tunnel  # noqa: F401

version = "0.6a"


def load_env(filename: Union[str, os.PathLike] = ".env", scan: bool = False) -> NoReturn:
    """Load .env files."""
    if scan:
        for file in os.listdir():
            if os.path.isfile(file) and file.endswith(".env"):
                dotenv.load_dotenv(dotenv_path=file, verbose=False)
    else:
        if os.path.isfile(filename):
            dotenv.load_dotenv(dotenv_path=filename, verbose=False)


load_env()
