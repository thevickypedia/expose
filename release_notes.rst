Release Notes
=============

0.4.5 (03/19/2023)
------------------
- Retain boto3 session throughout the process
- Remove hard coding

0.4.4 (03/19/2023)
------------------
- Minor improvements in functionality
- Create wrappers for env vars and fileio objects
- Remove f strings from logger
- Onboard to pypi with pyproject.toml
- Switch python-publish.yml to support pyproject.toml

0.4.3 (05/01/2022)
------------------
- Fix imports and remove redundancy
- Remove unused functions

0.4.2 (05/01/2022)
------------------
- Remove unnecessary args
- Fix imports and README.md
- Update docs version

0.4.1 (01/19/2022)
------------------
- Check for app running on port before initiating tunneling
- Flush screen output before carriage return
- Take optional args to terminate instance and delete security group
- Remove unnecessary args

0.4.0 (01/15/2022)
------------------
- Update python-publish.yml

0.3.9 (01/15/2022)
------------------
- Write file to server directly from github
- Avoid saving config files locally
- Fix logging

0.3.8 (01/15/2022)
------------------
- Remove print statements and create a default log formatter

0.3.7 (01/15/2022)
------------------
- Use sockets and channels for reverse ssh port forwarding
- Check for files after running SCP
- Convert port to integer using exception handler

0.3.6 (01/13/2022)
------------------
- Reduce `os.system` usage
- Add an exception handler for subprocess
- Remove unnecessary vars

0.3.5 (01/09/2022)
------------------
- Update module as stable

0.3.4 (01/06/2022)
------------------
- Fix intermittent IP info missing issue

0.3.3 (01/05/2022)
------------------
- Add an option for length of RSA signature
- Remove incorrect return statement

0.3.2 (01/05/2022)
------------------
- Remove `AMI_ID` from mandatory args
- Retrieve AMI_ID automatically
- Setup AWS defaults

0.3.1 (01/05/2022)
------------------
- Check `env vars`/`args` before startup
- Add default image id if region is us-west-2

0.3.0 (01/04/2022)
------------------
- Take `ORG` and `EMAIL` as both args and env vars

0.2.9 (01/04/2022)
------------------
- Update docs and make isort happy

0.2.8 (01/04/2022)
------------------
- Move `prefix` function to auxiliary.py
- Re-arrange args
- Update README.md and requirements.txt

0.2.7 (01/04/2022)
------------------
- Create SSL certificate by default
- Use paramiko to perform server copy
- Make application compatible as a perfect module

0.2.6 (01/04/2022)
------------------
- Download configuration files from git during run time
- Take all env vars as optional arguments during class initialization

0.2.5 (01/04/2022)
------------------
- Move configuration files into a dedicated directory

0.2.4 (01/03/2022)
------------------
- Fix `requirements.txt` path in `setup.py`

0.2.3 (01/03/2022)
------------------
- Update python-publish.yml

0.2.2 (01/03/2022)
------------------
- Try using `package_data` to include helpers directory

0.2.1 (01/03/2022)
------------------
- Remove find_packages

0.2.0 (01/03/2022)
------------------
- Try using find_packages to include helpers directory
- Update module name for docs

0.1.9 (01/03/2022)
------------------
- Add MANIFEST.in to include helpers directory
- Rename tunnel.py to expose.py

0.1.8 (01/03/2022)
------------------
- Bump version

0.1.7 (01/03/2022)
------------------
- Setup pypi publish

0.1.6 (01/03/2022)
------------------
- Create python-publish.yml

0.1.5 (01/03/2022)
------------------
- Change wait times and typos

0.1.4 (12/23/2021)
------------------
- Get name of the calling file gracefully
- Log the action in route_53.py
- Update README.md

0.1.3 (12/20/2021)
------------------
- Update README.md
- Get rid of hard coded / for path

0.1.2 (12/20/2021)
------------------
- Make expose as a CLI tool

0.1.1 (12/20/2021)
------------------
- Add lost changes on nginx_server.py

0.1.0 (12/20/2021)
------------------
- Add sphinx auto-gen docs
- Fix docstrings and module names

0.0.9 (12/20/2021)
------------------
- Format print statements in config to logger type
- Change some function names

0.0.8 (12/20/2021)
------------------
- Use `paramiko` for interactive ssh setup

0.0.7 (12/20/2021)
------------------
- Add boto3 error handling

0.0.6 (12/19/2021)
------------------
- Enable `https` for the endpoints
- Requires .pem files in .ssh or cwd

0.0.5 (12/19/2021)
------------------
- Add config files for SSL to enable https on the endpoint serving the app/api

0.0.4 (12/18/2021)
------------------
- Setup automatic configuration
- Delete Route53 record when tunneling is to be closed
- Onboard nginx.conf and server.conf

0.0.3 (12/18/2021)
------------------
- Onboard a script to add DNS records to a hosted zone
- Modify logger formatting

0.0.2 (12/18/2021)
------------------
- Replicate EC2 creation part from vpn-server
- Update .gitignore, LICENSE and README.md
- Add requirements.txt and expose.py

0.0.1 (12/18/2021)
------------------
- Initial commit
