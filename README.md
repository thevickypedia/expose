![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue)

###### Platform Supported
![Generic badge](https://img.shields.io/badge/Platform-MacOS|Windows-1f425f.svg)

###### Repo Stats
[![GitHub](https://img.shields.io/github/license/thevickypedia/expose)][LICENSE]
[![GitHub repo size](https://img.shields.io/github/repo-size/thevickypedia/expose)][API_REPO]
[![GitHub code size](https://img.shields.io/github/languages/code-size/thevickypedia/expose)][API_REPO]

###### Deployments
[![doc](https://github.com/thevickypedia/expose/actions/workflows/pages/pages-build-deployment/badge.svg)][gha_pages]
[![pypi](https://github.com/thevickypedia/expose/actions/workflows/python-publish.yml/badge.svg)][gha_pypi]
[![markdown](https://github.com/thevickypedia/expose/actions/workflows/markdown-validation.yml/badge.svg)][gha_markdown]

[![Pypi-format](https://img.shields.io/pypi/format/expose-localhost)](https://pypi.org/project/expose-localhost/#files)
[![Pypi-status](https://img.shields.io/pypi/status/expose-localhost)](https://pypi.org/project/expose-localhost)
[![sourcerank](https://img.shields.io/librariesio/sourcerank/pypi/expose-localhost)](https://libraries.io/pypi/expose-localhost)

# Expose localhost using EC2
Reverse proxy that creates a secure tunnel from public endpoint to locally running web service

### Setup
#### Environment Variables:
Environment variables can be loaded from any `.env` file.

- **PORT**: Port number that has to be exposed (on which a localhost `service/app/api` is running)

<br>

<details>
<summary><strong>Optional env</strong></summary>

- **OPEN_PORT**: Boolean flag to enable `ingress` and `egress` on the specified port. Defaults to `False`
- **CHANNEL_TIMEOUT**: Timeout in seconds to wait for an incoming channel connection. Defaults to `100`
- **IMAGE_ID**: ID of any public AMI with an Ubuntu OS. Defaults to a region specific image ID.
- **INSTANCE_TYPE**: Instance type for tunneling. Defaults to `t2.nano`
- **AWS_ACCESS_KEY**: Access key to access AWS resources. Defaults to `~/.aws/config`
- **AWS_SECRET_KEY**: Secret key to access AWS resources. Defaults to `~/.aws/config`
- **AWS_REGION_NAME**: Region name where the instance should live. Defaults to `US-WEST-2`
- **KEY_PAIR**: Name for the ec2 key pair file. Defaults to `expose_localhost`
- **SECURITY_GROUP**: Name for the security group to allow port access. Defaults to `Expose Localhost`
- **SERVER_INFO**: Name for the JSON file to store the configuration info. Defaults to `server_info.json`
- **EMAIL_ADDRESS**: Email address to create the self-signed SSL and private key. Defaults to `USER@expose-localhost.com`
- **ORGANIZATION**: Organization name for the certificate. Defaults to the AWS endpoint.
- **HOSTED_ZONE**: Hosted zone name registered using `route53`. *Example: `mywebsite.com`*
- **SUBDOMAIN**: Sub-domain that has to be added for the domain name. *Example: `tunnel`*
</details>

<details>
<summary><strong>Latency</strong></summary>

`CHANNEL_TIMEOUT` can be adjusted to improve latency depending on the application's role.

**Network Latency**

Shorter timeouts can make your server more responsive to incoming connections but may also lead to false negatives if network latency is high.
If connections take longer to establish due to network conditions, a short timeout might reject valid connections prematurely.

**Connection Rate**

If your server expects a high rate of incoming connections, and you want to process them quickly, a shorter timeout can be beneficial.
However, it also means that your server needs to be able to process connections rapidly.

**Resource Usage**

Short timeouts can lead to a higher rate of repeated checks, which may consume more CPU resources on the server.
Ensure that your server has the capacity to handle frequent connection checks, if you are setting `CHANNEL_TIMEOUT` too low.
</details>

<details>
<summary><strong>Custom endpoint</strong></summary>

The public DNS names for EC2 instances are long and messy. To avoid that, an `A` record can be added to the `route53` hosted zone.

:warning: &nbsp; Requires an active hosted zone on `route53`.

:bulb: &nbsp; `SUBDOMAIN.HOSTED_ZONE` will be the endpoint to access the localhost from public internet.
</details>

<details>
<summary><strong>SSL certificate</strong></summary>

- Securing the tunnel requires the certificate chain and the key file.
- The certificate and key files should be in `pem` format stored in current working directory.
- File names should be stored as `key_file` and `cert_file` env var.
- No certs? No problem. `expose` will generate a self-signed certificate and a private key automatically.

:warning: &nbsp; Some web browsers might throw a warning and some might even block a self-signed certificate/private CA.

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

<br>

<details>
<summary><strong>Troubleshooting</strong></summary>

> If `E: Could not get lock /var/lib/dpkg/lock-frontend` occurs during startup, simply rerun the script with start command.

> This occurs when `apt` hasn't released the resources yet. A retry logic is in place to delete the lock file automatically.
> However, if any such issues persist, re-running `tunnel.start()` will simply re-configure the instance entirely.
</details>

<details>
<summary><strong>Limitations</strong></summary>

Currently `expose` cannot handle, tunneling multiple port numbers without modifying the following env vars in the `.env` file.
```shell
KEY_PAIR        # SSH connection to AWS ec2
KEY_FILE        # Private key filename for self signed SSL
CERT_FILE       # Public certificate filename for self signed SSL
SERVER_INFO     # Filename to dump JSON data with server configuration information
SECURITY_GROUP  # Ingress and egress firewall rules to control traffic allowed via VPC
```
</details>

## Coding Standards
Docstring format: [`Google`](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) <br>
Styling conventions: [`PEP 8`](https://www.python.org/dev/peps/pep-0008/) <br>
Clean code with pre-commit hooks: [`flake8`](https://flake8.pycqa.org/en/latest/) and 
[`isort`](https://pycqa.github.io/isort/)

## [Release Notes][release-notes]
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
[![pypi-module](https://img.shields.io/badge/Software%20Repository-pypi-1f425f.svg)][pypi-read]

[https://pypi.org/project/expose-localhost/][pypi]

### Runbook
[![made-with-sphinx-doc](https://img.shields.io/badge/Code%20Docs-Sphinx-1f425f.svg)][sphinx-read]

[https://thevickypedia.github.io/expose/][docs]

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][LICENSE]

[LICENSE]: https://github.com/thevickypedia/expose/blob/main/LICENSE
[API_REPO]: https://api.github.com/repos/thevickypedia/expose
[pypi]: https://pypi.org/project/expose-localhost/
[pypi-read]: https://packaging.python.org/tutorials/packaging-projects/
[sphinx-read]: https://www.sphinx-doc.org/en/master/man/sphinx-autogen.html
[docs]: https://thevickypedia.github.io/expose/
[release-notes]: https://github.com/thevickypedia/expose/blob/main/release_notes.rst
[gha_pages]: https://github.com/thevickypedia/expose/actions/workflows/pages/pages-build-deployment
[gha_pypi]: https://github.com/thevickypedia/expose/actions/workflows/python-publish.yml
[gha_markdown]: https://github.com/thevickypedia/expose/actions/workflows/markdown-validation.yml
