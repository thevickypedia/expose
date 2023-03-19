# Expose localhost using EC2
Expose an app/api running on local host to public internet using AWS EC2

### Requirements
- Access to an AWS account.
- A `service/app/api` running on a specific port that has to be exposed to public internet.
- **[Optional]** A domain `example.com` hosted on `route53`.

### Setup
#### Environment Variables:
Environment variables can be loaded from a `.env` file.

**Mandatory Arg:**
- `PORT`: Port number that has to be exposed (on which a localhost `service/app/api` is running)

**Optional Args:**
- `AMI_ID`: ID of any public AMI with an Ubuntu OS. Defaults to a region specific image ID.
- `ACCESS_KEY`: Access key to access AWS resources. Defaults to `~/.aws/config`
- `SECRET_KEY`: Secret key to access AWS resources. Defaults to `~/.aws/config`
- `REGION_NAME`: Region name where the instance should live. Defaults to `US-WEST-2`
- `DOMAIN`: If the domain name is registered using `route53`. *Example: `mywebsite.com`*
- `SUBDOMAIN`: Sub-domain that has to be added for the domain name. *Example: `tunnel.mywebsite.com`*
- `EMAIL`: Email address to create the self-signed SSL and private key. Defaults to `USER@expose-localhost.com`
- `ORG`: Organization name for the certificate. Defaults to the AWS endpoint.

<details>
<summary><strong>Setup a custom endpoint</strong></summary>

The public DNS names for EC2 instances are long and messy. To avoid that, an `A` record can be added to the `route53` hosted zone.

:warning: &nbsp; Requires an active hosted zone on `route53`.

- `DOMAIN`: If the domain name is registered using `route53`. *Example: `mywebsite.com`*
- `SUBDOMAIN`: Sub-domain that has to be added for the domain name. *Example: `tunnel.mywebsite.com`*

&nbsp; &nbsp; &nbsp; &nbsp; :bulb: &nbsp; This will be the endpoint to access the localhost.

</details>

#### Certificate:
- Securing the tunnel requires the certificate chain and the key file.
- These two files should be saved as `cert.pem` and `key.pem` in either `~.ssh/*.pem` or within `expose` repository.
- No certs? No problem. [`expose`](https://github.com/thevickypedia/expose/blob/main/expose/helpers/cert.py) will 
generate a self-signed certificate and a private key automatically.

<details>
<summary><strong>Generate private SSL certificate</strong></summary>

Unfortunately not many SSL certificate providers give the liberty to download key files. But `expose`, can use private certificates.

:warning: &nbsp; Some web browsers might throw a warning and some might even block a self-signed certificate/private CA.

To manually generate a self-signed cert:

> `openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout ~/.ssh/key.pem -out ~/.ssh/cert.pem`

[OR]

Simply let `expose` create a self-signed SSL certificate and a private key.

- `EMAIL`: Email address to create the self-signed SSL and private key. Defaults to `USER@expose-localhost.com`
- `ORG`: Organization name for the certificate. Defaults to the AWS endpoint.

</details>

### Usage
###### Installation
```shell
python3 -m pip install expose-localhost
```

###### Start tunneling:
```python
import expose

tunnel = expose.Tunnel()
tunnel.start()
```

###### Stop tunneling:
```python
import expose

tunnel = expose.Tunnel()
tunnel.stop()
```

<details>
<summary><strong>Troubleshooting</strong></summary>

> If `E: Could not get lock /var/lib/dpkg/lock-frontend` occurs during startup, simply rerun the script with start command.
> This occurs when `apt` hasn't released the resources yet. Re-running `tunnel.start()` will simply re-configure the instance.

</details>

## Coding Standards
Docstring format: [`Google`](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) <br>
Styling conventions: [`PEP 8`](https://www.python.org/dev/peps/pep-0008/) <br>
Clean code with pre-commit hooks: [`flake8`](https://flake8.pycqa.org/en/latest/) and 
[`isort`](https://pycqa.github.io/isort/)

## [Release Notes](https://github.com/thevickypedia/expose/blob/main/release_notes.rst)
**Requirement**
```shell
python -m pip install changelog-generator
```

**Usage**
```shell
changelog reverse -f release_notes.rst -t 'Release Notes'
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

&copy; Vignesh Sivanandha Rao

Licensed under the [MIT License](https://github.com/thevickypedia/expose/blob/main/LICENSE)
