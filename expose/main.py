import json
import logging
import os
import time

import boto3
import requests
import urllib3.exceptions
from botocore.exceptions import ClientError

from .helpers.auxiliary import IP_INFO
from .helpers.cert import generate_cert
from .helpers.config import EnvConfig, fileio, wait
from .helpers.defaults import AWSDefaults
from .helpers.logger import LOGGER
from .helpers.route_53 import change_record_set
from .helpers.server import Server

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable warnings for self-signed certificates

CONFIGURATION_LOCATION = 'https://raw.githubusercontent.com/thevickypedia/expose/main/configuration/'


class Tunnel:
    """Initiates ``Tunnel`` object to spin up an EC2 instance with a pre-configured AMI which acts as a tunnel.

    >>> Tunnel

    """

    def __init__(self, port: int = None, image_id: str = None, domain: str = None,
                 subdomain: str = None, aws_access_key: str = None, aws_secret_key: str = None,
                 aws_region_name: str = None, email_address: str = None, organization: str = None,
                 logger: logging.Logger = None):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            port: Port number where the application/API is running in localhost.
            image_id: Takes image ID as an argument. Defaults to ``ami_id`` in environment variable.
            domain: Name of the hosted zone in which an ``A`` record has to be added. [``example.com``]
            subdomain: Subdomain using which the localhost has to be accessed. [``tunnel`` or ``tunnel.example.com``]
            aws_access_key: Access token for AWS account.
            aws_secret_key: Secret ID for AWS account.
            aws_region_name: Region where the instance should live. Defaults to ``us-west-2``

        See Also:
            - If no values (for aws authentication) are passed during object initialization, script checks for env vars.
            - If the environment variables are ``null``, gets the default credentials from ``~/.aws/credentials``.
        """
        env = EnvConfig()

        # AWS client and resource setup
        self.region = (aws_region_name or env.aws_region_name).lower()
        session = boto3.Session(region_name=aws_region_name or env.aws_region_name,
                                aws_access_key_id=aws_access_key or aws_access_key,
                                aws_secret_access_key=aws_secret_key or aws_secret_key)
        self.ec2_client = session.client(service_name='ec2')
        self.ec2_resource = session.resource(service_name='ec2')
        self.route53_client = session.client(service_name='route53')

        # Tunnelling requirements setup
        self.image_id = image_id or env.image_id
        self.port = port or env.port
        self.domain_name = domain or env.domain
        self.subdomain = subdomain or env.subdomain
        self.email_address = email_address or env.email_address
        self.organization = organization or env.organization

        self.logger = logger or LOGGER

    def _get_image_id(self) -> None:
        """Fetches AMI ID from public images."""
        if self.region.startswith('us'):
            self.image_id = AWSDefaults.IMAGE_MAP[self.region]
            return

        try:
            images = self.ec2_client.describe_images(Filters=[
                {
                    'Name': 'name',
                    'Values': [AWSDefaults.DEFAULT_AMI_NAME]
                },
            ])
        except ClientError as error:
            self.logger.warning('API call to retrieve AMI ID for %s has failed.', self.region)
            self.logger.error(error)
            raise

        if not (retrieved := images.get('Images', [{}])[0].get('ImageId')):
            raise LookupError(f'Failed to retrieve AMI ID for {self.region}. Set one manually.')
        self.image_id = retrieved

    def _create_key_pair(self) -> bool:
        """Creates a ``KeyPair`` of type ``RSA`` stored as a ``PEM`` file to use with ``OpenSSH``.

        Returns:
            bool:
            Flag to indicate the calling function if a ``KeyPair`` was created.
        """
        try:
            response = self.ec2_client.create_key_pair(
                KeyName=fileio.tunnel_raw,
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidKeyPair.Duplicate)' in error and fileio.tunnel_raw in error:
                self.logger.warning('Found an existing KeyPair named: Tunnel. Re-creating it.')
                self._delete_key_pair()
                self._create_key_pair()
                return True
            self.logger.warning('API call to create key pair has failed.')
            self.logger.error(error)
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            with open(fileio.tunnel, 'w') as file:
                file.write(response.get('KeyMaterial'))
            self.logger.info('Stored KeyPair as %s', fileio.tunnel)
            return True
        else:
            self.logger.error('Unable to create a key pair: %s', fileio.tunnel)

    def _get_vpc_id(self) -> str or None:
        """Gets the default VPC id.

        Returns:
            str or None:
            Default VPC id.
        """
        try:
            response = self.ec2_client.describe_vpcs()
        except ClientError as error:
            self.logger.warning('API call to get VPC id has failed.')
            self.logger.error(error)
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')
            self.logger.info('Got the default VPC: %s', vpc_id)
            return vpc_id
        else:
            self.logger.error('Unable to get VPC ID')

    def _authorize_security_group(self, security_group_id: str, public_ip: str) -> bool:
        """Authorizes the security group for certain ingress list.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        Returns:
            bool:
            Flag to indicate the calling function whether the security group was authorized.
        """
        try:
            response = self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     # 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # Makes instanceID accessible from anywhere but insecure
                     'IpRanges': [{'CidrIp': f'{public_ip}/32'}, {'CidrIp': f"{IP_INFO.get('ip')}/32"}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 443,
                     'ToPort': 443,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 80,
                     'ToPort': 80,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                ])
        except ClientError as error:
            error = str(error)
            if '(InvalidPermission.Duplicate)' in error:
                self.logger.warning('Identified same permissions in an existing SecurityGroup: %s', security_group_id)
                return True
            self.logger.warning('API call to authorize the security group %s has failed.', security_group_id)
            self.logger.error(error)
            return False
        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info('Ingress Successfully Set for SecurityGroup %s', security_group_id)
            for sg_rule in response['SecurityGroupRules']:
                log = 'Allowed protocol: ' + sg_rule['IpProtocol'] + ' '
                if sg_rule['FromPort'] == sg_rule['ToPort']:
                    log += 'on port: ' + str(sg_rule['ToPort']) + ' '
                else:
                    log += 'from port:  ' f"{sg_rule['FromPort']} to port: {sg_rule['ToPort']}" + ' '
                self.logger.info(log + 'with CIDR ' + sg_rule['CidrIpv4'])
            return True
        else:
            self.logger.info('Failed to set Ingress: %s', response)

    def _create_security_group(self) -> str or None:
        """Calls the class method ``_get_vpc_id`` and uses the VPC ID to create a ``SecurityGroup`` for the instance.

        Returns:
            str or None:
            SecurityGroup ID
        """
        if not (vpc_id := self._get_vpc_id()):
            return

        try:
            response = self.ec2_client.create_security_group(
                GroupName='Expose Localhost',
                Description='Security Group to allow certain port ranges for VM.',
                VpcId=vpc_id
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidGroup.Duplicate)' in error and 'Expose Localhost' in error:
                self.logger.warning('Found an existing SecurityGroup named: Expose Localhost. Reusing it.')
                response = self.ec2_client.describe_security_groups(
                    Filters=[
                        dict(Name='group-name', Values=['Expose Localhost'])
                    ]
                )
                group_id = response['SecurityGroups'][0]['GroupId']
                return group_id
            self.logger.warning('API call to create security group has failed.')
            self.logger.error(error)
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            security_group_id = response['GroupId']
            self.logger.info('Security Group created %s in VPC %s', security_group_id, vpc_id)
            return security_group_id
        else:
            self.logger.error('Failed to created the SecurityGroup')

    def _create_ec2_instance(self) -> str or None:
        """Creates an EC2 instance of type ``t2.nano`` with the pre-configured AMI id.

        Returns:
            str or None:
            Instance ID.
        """
        if not self._create_key_pair():
            return

        if not (security_group_id := self._create_security_group()):
            self._delete_key_pair()
            return

        try:
            response = self.ec2_client.run_instances(
                InstanceType="t2.nano",
                MaxCount=1,
                MinCount=1,
                ImageId=self.image_id,
                KeyName=fileio.tunnel_raw,
                SecurityGroupIds=[security_group_id]
            )
        except ClientError as error:
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            self.logger.warning('API call to create instance has failed.')
            self.logger.error(error)
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            instance_id = response.get('Instances')[0].get('InstanceId')
            self.logger.info('Created the EC2 instance: %s', instance_id)
            return instance_id, security_group_id
        else:
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            self.logger.error('Failed to create an EC2 instance.')

    def _delete_key_pair(self) -> bool:
        """Deletes the ``KeyPair``.

        Returns:
            bool:
            Flag to indicate the calling function if the KeyPair was deleted.
        """
        try:
            response = self.ec2_client.delete_key_pair(
                KeyName=fileio.tunnel_raw
            )
        except ClientError as error:
            self.logger.warning('API call to delete the key Tunnel has failed.')
            self.logger.error(error)
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info('%s has been deleted from KeyPairs.', fileio.tunnel_raw)
            if os.path.exists(fileio.tunnel):
                os.chmod(fileio.tunnel, int('700', base=8) or 0o700)
                os.remove(fileio.tunnel)
            return True
        else:
            self.logger.error('Failed to delete the key: Tunnel')

    def _delete_security_group(self, security_group_id: str) -> bool:
        """Deletes the security group.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        Returns:
            bool:
            Flag to indicate the calling function whether the SecurityGroup was deleted.
        """
        try:
            response = self.ec2_client.delete_security_group(
                GroupId=security_group_id
            )
        except ClientError as error:
            self.logger.warning('API call to delete the Security Group %s has failed.', security_group_id)
            self.logger.error(error)
            if '(InvalidGroup.NotFound)' in str(error):
                return True
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info('%s has been deleted from Security Groups.', security_group_id)
            return True
        else:
            self.logger.error('Failed to delete the SecurityGroup: %s', security_group_id)

    def _terminate_ec2_instance(self, instance_id: str) -> bool:
        """Terminates the requested instance.

        Args:
            instance_id: Takes instance ID as an argument. Defaults to the instance that was created previously.

        Returns:
            bool:
            Flag to indicate the calling function whether the instance was terminated.
        """
        try:
            response = self.ec2_client.terminate_instances(
                InstanceIds=[instance_id]
            )
        except ClientError as error:
            self.logger.warning('API call to terminate the instance has failed.')
            self.logger.error(error)
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info('InstanceId %s has been set to terminate.', instance_id)
            return True
        else:
            self.logger.error('Failed to terminate the InstanceId: %s', instance_id)

    def _instance_info(self, instance_id: str) -> tuple or None:
        """Makes a ``describe_instance_status`` API call to get the status of the instance that was created.

        Args:
            instance_id: Takes the instance ID as an argument.

        Returns:
            tuple or None:
            A tuple object of Public DNS Name and Public IP Address.
        """
        self.logger.info('Waiting for the instance to go live. Est time: %d seconds remaining', wait.instance_warmup)
        time.sleep(wait.instance_warmup)
        while True:
            time.sleep(wait.instance_warmup_refresh)
            try:
                response = self.ec2_client.describe_instance_status(
                    InstanceIds=[instance_id]
                )
            except ClientError as error:
                self.logger.warning('API call to describe instance has failed.')
                self.logger.error(error)
                return

            if response.get('ResponseMetadata').get('HTTPStatusCode') != 200:
                continue
            if status := response.get('InstanceStatuses'):
                if status[0].get('InstanceState').get('Name') == 'running':
                    instance_info = self.ec2_resource.Instance(instance_id)
                    return instance_info.public_dns_name, instance_info.public_ip_address

    def start(self) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the ec2 instance."""
        try:
            self.port = int(self.port)
        except (TypeError, ValueError):
            self.logger.error("Port number is mandatory and should be an integer to initiate tunneling. "
                              "Received '%s'", self.port)
            return

        if os.path.isfile(fileio.server_info) and os.path.isfile(fileio.tunnel):
            self.logger.warning('Received request to start VM, but looks like a session is up and running already.')
            self.logger.warning('Initiating re-configuration.')
            with open('server_info.json') as file:
                data = json.load(file)
            self._configure_vm(public_dns=data.get('public_dns'), public_ip=data.get('public_ip'))
            return

        if not all((self.domain_name, self.subdomain)):
            self.logger.warning("DOMAIN and SUBDOMAIN gives a customized access to the tunnel.")
        if not all((self.email_address, self.organization)):
            self.logger.warning("EMAIL_ADDRESS and ORGANIZATION can be used to create a customized certificate.")

        if not self.image_id:
            self._get_image_id()
            self.logger.info("AMI ID was not set. Using the default AMI ID '%s' for the region '%s'",
                             self.image_id, self.region)

        if instance_basic := self._create_ec2_instance():
            instance_id, security_group_id = instance_basic
        else:
            return

        if instance := self._instance_info(instance_id=instance_id):
            public_dns, public_ip = instance
        else:
            return

        if not self._authorize_security_group(security_group_id=security_group_id, public_ip=public_ip):
            self._terminate_ec2_instance(instance_id=instance_id)
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            return

        instance_info = {
            'instance_id': instance_id,
            'public_dns': public_dns,
            'public_ip': public_ip,
            'security_group_id': security_group_id,
            'ssh_endpoint': f'ssh -i {fileio.tunnel} ubuntu@{public_dns}',
            'start_tunneling': f"ssh -i {fileio.tunnel} -R 8080:localhost:{self.port} ubuntu@{public_dns}"
        }

        os.chmod(fileio.tunnel, int('400', base=8) or 0o400)

        with open(fileio.server_info, 'w') as file:
            json.dump(instance_info, file, indent=2)

        self.logger.info('Waiting for SSH origin to be active. Est time remaining: %d seconds.', wait.ssh_warmup)
        time.sleep(wait.ssh_warmup)

        self._configure_vm(public_dns=public_dns, public_ip=public_ip)

    def _configure_vm(self, public_dns: str, public_ip: str):
        """Configures the ec2 instance to take traffic from localhost.

        Args:
            public_dns: Public DNS name of the EC2 that was created.
            public_ip: Public IP of the EC2 that was created.
        """
        self.logger.info('Gathering pieces for configuration.')
        custom_servers = f"{public_dns} {public_ip}"

        endpoint = None
        if self.domain_name and self.subdomain:
            if self.subdomain.endswith(self.domain_name):
                endpoint = self.subdomain
                custom_servers += f' {self.subdomain}'
            else:
                endpoint = f'{self.subdomain}.{self.domain_name}'
                custom_servers += f' {self.subdomain}.{self.domain_name}'

        nginx_server = Server(hostname=public_dns, pem_file=fileio.tunnel, logger=self.logger)

        def _file_io_uploader(source_file: str, destination_file: str) -> None:
            """Reads a file in localhost and writes it within SSH connection.

            Args:
                source_file: Name of the source file in localhost.
                destination_file: Name of the destination file in the server.
            """
            with open(source_file) as f:
                nginx_server.server_write(data={destination_file: f.read()})

        def _download_config_file(filename: str):
            """Downloads configuration files from GitHub.

            Args:
                filename: Name of the file that has to be downloaded.

            Returns:
                str:
                Returns the data of the file as a string.
            """
            self.logger.info('Downloading the configuration file: %s.', filename)
            response = requests.get(url=f'{CONFIGURATION_LOCATION}{filename}')
            if not response.ok:
                raise ConnectionError(f'Failed to download the config file: {filename}')
            return response.text.replace('SERVER_NAME_HERE', custom_servers)

        download_and_copy = {"server.conf": _download_config_file(filename="server.conf")}
        if os.path.isdir(fileio.ssh_home) and \
                os.path.isfile(os.path.join(fileio.ssh_home, "key.pem")) and \
                os.path.isfile(os.path.join(fileio.ssh_home, "cert.pem")):
            self.logger.info('Found certificate and key in %s', fileio.ssh_home)
            _file_io_uploader(source_file=os.path.join(fileio.ssh_home, "key.pem"), destination_file="key.pem")
            _file_io_uploader(source_file=os.path.join(fileio.ssh_home, "cert.pem"), destination_file="cert.pem")
            download_and_copy["options-ssl-nginx.conf"] = _download_config_file(filename="options-ssl-nginx.conf")
            download_and_copy["nginx.conf"] = _download_config_file(filename="nginx-ssl.conf")
        elif os.path.isfile(os.path.join(fileio.current_dir, "cert.pem")) and \
                os.path.isfile(os.path.join(fileio.current_dir, "key.pem")):
            self.logger.info('Found certificate and key in %s', fileio.current_dir)
            _file_io_uploader(source_file=os.path.join(fileio.current_dir, "cert.pem"), destination_file="cert.pem")
            _file_io_uploader(source_file=os.path.join(fileio.current_dir, "key.pem"), destination_file="key.pem")
            download_and_copy["options-ssl-nginx.conf"] = _download_config_file(filename="options-ssl-nginx.conf")
            download_and_copy["nginx.conf"] = _download_config_file(filename="nginx-ssl.conf")
        elif generate_cert(common_name=endpoint or public_dns, email_address=self.email_address,
                           organization_name=self.organization):
            self.logger.info('Generated self-signed SSL certificate and private key.')
            _file_io_uploader(source_file=os.path.join(fileio.current_dir, "cert.pem"), destination_file="cert.pem")
            _file_io_uploader(source_file=os.path.join(fileio.current_dir, "key.pem"), destination_file="key.pem")
            download_and_copy["options-ssl-nginx.conf"] = _download_config_file(filename="options-ssl-nginx.conf")
            download_and_copy["nginx.conf"] = _download_config_file(filename="nginx-ssl.conf")
        else:
            self.logger.warning('Failed to generate self-signed SSL certificate and private key.')
            download_and_copy["nginx.conf"] = _download_config_file(filename="nginx-non-ssl.conf")

        self.logger.info('Copying configuration files to %s', public_dns)
        nginx_server.server_write(data=download_and_copy)

        self.logger.info('Configuring nginx server.')
        nginx_status = nginx_server.run_interactive_ssh(
            commands=(
                "sudo apt-get update -y",
                "echo Y | sudo -S apt-get install nginx -y",
                "sudo mv /home/ubuntu/server.conf /etc/nginx/conf.d/server.conf",
                "sudo mv /home/ubuntu/nginx.conf /etc/nginx/nginx.conf",
                "sudo systemctl restart nginx"
            )
        )
        if not nginx_status:
            self.logger.error('Nginx server was not configured. Cleaning up AWS resources acquired.')
            self.stop()
            return

        self.logger.info('Nginx server was configured successfully.')
        protocol = 'https' if download_and_copy.get("options-ssl-nginx.conf") else 'http'
        if endpoint:
            change_record_set(dns_name=self.domain_name, source=self.subdomain, destination=public_ip, record_type='A',
                              logger=self.logger, client=self.route53_client)
            self.logger.info('%s://%s -> http://localhost:%d', protocol, endpoint, self.port)
        else:
            self.logger.info('%s://%s -> http://localhost:%d', protocol, public_dns, self.port)

        self.logger.info('Initiating tunnel')
        nginx_server.initiate_tunnel(port=self.port)

    def stop(self, partial: bool = False, instance_id: str = None, security_group_id: str = None) -> None:
        """Disables tunnelling by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        Args:
            partial: Flag to indicate whether the ``SecurityGroup`` has to be removed.
            instance_id: Instance that has to be terminated.
            security_group_id: Security group that has to be removed.
        """
        if not os.path.exists(fileio.server_info) and not instance_id and not security_group_id:
            self.logger.info('Input file: server_info.json is missing. CANNOT proceed.')
            return

        with open(fileio.server_info) as file:
            data = json.load(file)

        if self._delete_key_pair() and self._terminate_ec2_instance(instance_id=instance_id or data.get('instance_id')):
            wait_for_sg = True
        else:
            wait_for_sg = False
        if self.domain_name and self.subdomain:
            change_record_set(dns_name=self.domain_name, source=self.subdomain, destination=data.get('public_ip'),
                              record_type='A', action='DELETE', logger=self.logger, client=self.route53_client)
        if partial:
            return
        if wait_for_sg:
            self.logger.info('Waiting for dependent objects to delete SecurityGroup. Est time remaining: %d seconds.',
                             wait.unhook_sg)
            time.sleep(wait.unhook_sg)
        while True:
            if self._delete_security_group(security_group_id=security_group_id or data.get('security_group_id')):
                break
            else:
                time.sleep(wait.unhook_sg_refresh)
        os.remove(fileio.server_info) if os.path.isfile(fileio.server_info) else None
