Release Notes
=============

v0.6.9a (09/22/2023)
--------------------
- Add pre-release before optimized stable version

v0.6.2a (09/20/2023)
--------------------
- Folder restructure
- Remove redundancies
- Update README.md and docs

v0.6b (09/18/2023)
------------------
- Release beta version after using pydantic for validations

v0.6a (09/18/2023)
------------------
- Release alpha version after major restructure

0.5 (04/07/2023)
----------------
- Load/scan any `.env` file during startup
- Log daemon services launched in the background
- Change list to tuple wherever possible
- Unhook version number dependency on release notes

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

0.2.7 (01/04/2022)
------------------
- Create SSL certificate by default
- Use paramiko to perform server copy
- Make application compatible as a perfect module

0.2.6 (01/04/2022)
------------------
- Download configuration files from git during run time
- Take all env vars as optional arguments during class initialization

0.2.4 (01/03/2022)
------------------
- Fix `requirements.txt` path in `setup.py`

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
