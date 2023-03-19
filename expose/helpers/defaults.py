class AWSDefaults:
    """Default values for missing AWS configuration.

    >>> AWSDefaults

    """

    DEFAULT_AMI_NAME = 'aerospike-ubuntu-20.04-20211114101915'

    IMAGE_MAP = {
        "us-east-2": "ami-0971e839208a0d58a",
        "us-east-1": "ami-0eaca42ad8ff8647d",
        "us-west-1": "ami-0005fe7be6ce06e3c",
        "us-west-2": "ami-06e20d17437157772"
    }
