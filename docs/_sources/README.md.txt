# Expose localhost using EC2
Reverse proxy that creates a secure tunnel from public endpoint to locally running web service

### Requirements
- Access to an AWS account and [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#getting-started-install-instructions) configured.
- A `service/app/api` running on a specific port that has to be exposed to public internet.
- **[Optional]** A domain `example.com` hosted on `route53`.

### Setup
#### Environment Variables:
Environment variables can be loaded from a `.env` file.

**Mandatory Arg:**
- **PORT**: Port number that has to be exposed (on which a localhost `service/app/api` is running)

**Optional Args:**
- **IMAGE_ID**: ID of any public AMI with an Ubuntu OS. Defaults to a region specific image ID.
- **AWS_ACCESS_KEY**: Access key to access AWS resources. Defaults to `~/.aws/config`
- **AWS_SECRET_KEY**: Secret key to access AWS resources. Defaults to `~/.aws/config`
- **AWS_REGION_NAME**: Region name where the instance should live. Defaults to `US-WEST-2`
- **KEY_PAIR**: Name for the ec2 key pair file. Defaults to `expose_localhost`
- **SECURITY_GROUP**: Name for the security group to allow port access. Defaults to `Expose Localhost`
- **SERVER_INFO**: Name for the JSON file to store the configuration info. Defaults to `server_info.json`

<details>
<summary><strong>Setup a custom endpoint</strong></summary>

The public DNS names for EC2 instances are long and messy. To avoid that, an `A` record can be added to the `route53` hosted zone.

:warning: &nbsp; Requires an active hosted zone on `route53`.

- **HOSTED_ZONE**: Hosted zone name registered using `route53`. *Example: `mywebsite.com`*
- **SUBDOMAIN**: Sub-domain that has to be added for the domain name. *Example: `tunnel`*

&nbsp; &nbsp; &nbsp; &nbsp; :bulb: &nbsp; `tunnel.mywebsite.com` will be the endpoint to access the localhost from public internet.

</details>

#### Certificate:
- Securing the tunnel requires the certificate chain and the key file.
- The certificate and key files should be in `pem` format stored within `expose` directory.
- File names should be stored as `key_file` and `cert_file` env var.
- No certs? No problem. `expose` will generate a self-signed certificate and a private key automatically.

<details>
<summary><strong>Generate self-signed SSL certificate</strong></summary>

:warning: &nbsp; Some web browsers might throw a warning and some might even block a self-signed certificate/private CA.

`expose` creates a self-signed SSL certificate and a private key by default.

- **EMAIL_ADDRESS**: Email address to create the self-signed SSL and private key. Defaults to `USER@expose-localhost.com`
- **ORGANIZATION**: Organization name for the certificate. Defaults to the AWS endpoint.

**Manually generate self-signed certificate**
> `openssl req -newkey rsa:2048 -sha256 -nodes -keyout private.pem -x509 -days 365 -out public.pem -subj "/C=US/ST=New York/L=Brooklyn/O=Example Brooklyn Company/CN=tunnel.example.com"`

**To verify the generated certificate**
> `openssl x509 -inform pem -in public.pem -noout -text`

</details>

### Usage
###### Installation
```shell
python3 -m pip install expose-localhost
```

###### Tunneling:
```python
import os

os.environ['env_file'] = 'custom'  # to load a custom .env file

import expose

# Instantiate object
tunnel = expose.Tunnel()

# Start tunneling
tunnel.start()

# set 'purge' flag to 'True' to reclaim AWS resources if configuration fails
# tunnel.start(purge=True)

# Stop tunneling - deletes all AWS resources acquired
tunnel.stop()
```

<details>
<summary><strong>Troubleshooting</strong></summary>

> If `E: Could not get lock /var/lib/dpkg/lock-frontend` occurs during startup, simply rerun the script with start command.
> This occurs when `apt` hasn't released the resources yet. Re-running `tunnel.start()` will simply re-configure the instance.

</details>

### Limitations
Currently `expose` cannot handle, tunneling multiple port numbers without modifying the following env vars in the `.env` file.
```shell
KEY_PAIR        # SSH connection to AWS ec2
KEY_FILE        # Private key filename for self signed SSL
CERT_FILE       # Public certificate filename for self signed SSL
SERVER_INFO     # Filename to dump JSON data with server configuration information
SECURITY_GROUP  # Ingress and egress firewall rules to control traffic allowed via VPC
```

## Coding Standards
Docstring format: [`Google`](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) <br>
Styling conventions: [`PEP 8`](https://www.python.org/dev/peps/pep-0008/) <br>
Clean code with pre-commit hooks: [`flake8`](https://flake8.pycqa.org/en/latest/) and 
[`isort`](https://pycqa.github.io/isort/)

## [Release Notes](https://github.com/thevickypedia/expose/blob/main/release_notes.rst)
**Requirement**
```shell
python -m pip install gitverse
```

**Usage**
```shell
gitverse-release reverse -f release_notes.rst -t 'Release Notes'
```

## Linting
`PreCommit` will ensure linting, and the doc creation are run on every commit.

**Requirement**
```shell
pip install sphinx==5.1.1 pre-commit recommonmark
```

**Usage**
```shell
pre-commit run --all-files
```

### Pypi Package
[![pypi-module](https://img.shields.io/badge/Software%20Repository-pypi-1f425f.svg)](https://packaging.python.org/tutorials/packaging-projects/)

[https://pypi.org/project/expose-localhost/](https://pypi.org/project/expose-localhost/)

### Runbook
[![made-with-sphinx-doc](https://img.shields.io/badge/Code%20Docs-Sphinx-1f425f.svg)](https://www.sphinx-doc.org/en/master/man/sphinx-autogen.html)

[https://thevickypedia.github.io/expose/](https://thevickypedia.github.io/expose/)

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License](https://github.com/thevickypedia/expose/blob/main/LICENSE)
