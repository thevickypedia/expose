# Expose localhost using EC2
Expose an app/api running on local host to public internet using AWS EC2

### Requirements
- Access to an AWS account.
- A `service/app/api` running on a specific port that has to be exposed to public internet.
- **[Optional]** A domain `example.com` hosted on `route53`.

### Setup
#### Environment Variables:
- `AMI_ID`: ID of any public AMI with an Ubuntu OS.
- `PORT`: Port number on which a localhost `service/app/api` is running.

&nbsp; &nbsp; &nbsp; &nbsp; :bulb: &nbsp; Can also be passed as an arg. *Example: `python expose.py start 2021`*

<details>
<summary><strong>Setup a custom endpoint</strong></summary>

The public DNS names for EC2 instances are long and messy. To avoid that, an `A` record can be added to the `route53` hosted zone.

- **[Optional]** `DOMAIN`: If the domain name is registered using `route53`. *Example: `mywebsite.com`*
- **[Optional]** `SUBDOMAIN`: Sub-domain that has to be added for the domain name. *Example: `tunnel.mywebsite.com`*

&nbsp; &nbsp; &nbsp; &nbsp; :bulb: &nbsp; This will be the endpoint to access the localhost.

</details>

#### Certificate:
- [`expose`](https://github.com/thevickypedia/expose) uses downloaded certs for SSL handshake.
- Securing the tunnel requires the certificate chain and the key file.
- These two files should be saved as `cert.pem` and `key.pem` in either `~.ssh/*.pem` or within `expose` repository.
- No certs? No problem. [`expose`](https://github.com/thevickypedia/expose) still works without certificates. The `nginx` sever is configured accordingly.

<details>
<summary><strong>Generate private SSL certificate</strong></summary>

Unfortunately not many SSL certificate providers give the liberty to download key files. But `expose`, can use private certificates.

> `openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout ~/.ssh/key.pem -out ~/.ssh/cert.pem`

</details>

#### CLI commands

Startup tunneling:
- `python expose.py start 2021`: Takes the port number as the second arg.
- `python expose.py start`: Port number can also be stored as an env var `PORT`.

Shutdown tunnel:
`python expose.py stop`

<details>
<summary><strong>Troubleshooting</strong></summary>

> If `E: Could not get lock /var/lib/dpkg/lock-frontend` occurs during startup, simply rerun the script with start command.
> This occurs when `apt` hasn't released the resources yet.

</details>

#### Linting
`PreCommit` will ensure linting, and the doc creation are run on every commit.

#### Requirement
`pip install --no-cache --upgrade sphinx pre-commit recommonmark`

#### Usage
`pre-commit run --all-files`

### Runbook
[![made-with-sphinx-doc](https://img.shields.io/badge/Code%20Docs-Sphinx-1f425f.svg)](https://www.sphinx-doc.org/en/master/man/sphinx-autogen.html)

[https://thevickypedia.github.io/expose/](https://thevickypedia.github.io/expose/)

## License & copyright

&copy; Vignesh Sivanandha Rao

Licensed under the [MIT License](https://github.com/thevickypedia/expose/blob/main/LICENSE)
