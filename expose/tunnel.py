import json
import logging
from os import environ, getcwd, path, remove, rename, system
from subprocess import check_output
from time import perf_counter

import requests
from boto3 import client, resource
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from expose.helpers.auxiliary import (DATETIME_FORMAT, IP_INFO, sleeper,
                                      time_converter)
from expose.helpers.cert import generate_cert
from expose.helpers.defaults import AWSDefaults
from expose.helpers.nginx_server import ServerConfig
from expose.helpers.route_53 import change_record_set

disable_warnings(InsecureRequestWarning)  # Disable warnings for self-signed certificates

if path.isfile('.env'):
    load_dotenv(dotenv_path='.env', verbose=True, override=True)

SEP = path.sep
HOME_DIR = path.expanduser('~') + SEP
CURRENT_DIR = getcwd() + SEP
CONFIGURATION_FILES = [f'{CURRENT_DIR}server.conf', f'{CURRENT_DIR}nginx-ssl.conf',
                       f'{CURRENT_DIR}nginx-non-ssl.conf', f'{CURRENT_DIR}options-ssl-nginx.conf']
CONFIGURATION_LOCATION = 'https://raw.githubusercontent.com/thevickypedia/expose/main/configuration/'


class Tunnel:
    """Initiates ``Tunnel`` object to spin up an EC2 instance with a pre-configured AMI which acts as a tunnel.

    >>> Tunnel

    """

    def __init__(self, port: int = environ.get('PORT'),
                 image_id: str = environ.get('AMI_ID'),
                 domain_name: str = environ.get('DOMAIN'),
                 subdomain: str = environ.get('SUBDOMAIN'),
                 aws_access_key: str = environ.get('ACCESS_KEY'),
                 aws_secret_key: str = environ.get('SECRET_KEY'),
                 aws_region_name: str = environ.get('REGION_NAME', 'us-west-2'),
                 email_address: str = environ.get('EMAIL'),
                 organization: str = environ.get('ORG')):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            port: Port number where the application/API is running in localhost.
            image_id: Takes image ID as an argument. Defaults to ``ami_id`` in environment variable.
            domain_name: Name of the hosted zone in which an ``A`` record has to be added. [``example.com``]
            subdomain: Subdomain using which the localhost has to be accessed. [``tunnel`` or ``tunnel.example.com``]
            aws_access_key: Access token for AWS account.
            aws_secret_key: Secret ID for AWS account.
            aws_region_name: Region where the instance should live. Defaults to ``us-west-2``

        See Also:
            - If no values (for aws authentication) are passed during object initialization, script checks for env vars.
            - If the environment variables are ``null``, gets the default credentials from ``~/.aws/credentials``.
        """
        # Hard-coded certificate file name, server information file name, security group name
        self.key_name = 'Tunnel'
        self.server_file = 'server_info.json'
        self.security_group_name = 'Expose Localhost'

        # Logger setup
        self.logger = logging.getLogger(__name__)
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
            datefmt=DATETIME_FORMAT
        )
        handler = logging.StreamHandler()
        handler.setFormatter(fmt=formatter)
        handler.setLevel(level=logging.DEBUG)
        self.logger.addHandler(hdlr=handler)
        self.logger.setLevel(level=logging.DEBUG)

        # AWS client and resource setup
        self.region = aws_region_name.lower()
        if not AWSDefaults.REGIONS.get(aws_region_name):
            raise ValueError(f'Incorrect region name. {aws_region_name} does not exist.')
        self.ec2_client = client(service_name='ec2', region_name=aws_region_name,
                                 aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
        self.ec2_resource = resource(service_name='ec2', region_name=aws_region_name,
                                     aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)

        # Tunnelling requirements setup
        self.image_id = image_id
        self.port = port
        self.domain_name = domain_name
        self.subdomain = subdomain
        self.email_address = email_address
        self.organization = organization

    def __del__(self):
        """Destructor to print the run time at the end."""
        self.logger.info(f'Total runtime: {time_converter(perf_counter())}')

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
            self.logger.error(f'API call to retrieve AMI ID for {self.region} has failed.\n{error}')
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
                KeyName=self.key_name,
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidKeyPair.Duplicate)' in error and self.key_name in error:
                self.logger.warning(f'Found an existing KeyPair named: {self.key_name}. Re-creating it.')
                self._delete_key_pair()
                self._create_key_pair()
                return True
            self.logger.error(f'API call to create key pair has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'Successfully created a key pair named: {self.key_name}')
            with open(f'{self.key_name}.pem', 'w') as file:
                file.write(response.get('KeyMaterial'))
            self.logger.info(f'Stored the certificate as {self.key_name}.pem')
            return True
        else:
            self.logger.error(f'Unable to create a key pair: {self.key_name}')

    def _get_vpc_id(self) -> str or None:
        """Gets the default VPC id.

        Returns:
            str or None:
            Default VPC id.
        """
        try:
            response = self.ec2_client.describe_vpcs()
        except ClientError as error:
            self.logger.error(f'API call to get VPC id has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')
            self.logger.info(f'Got the default VPC: {vpc_id}')
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
                     # 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # Makes instance accessible from anywhere but insecure
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
                self.logger.warning(f'Identified same permissions in an existing SecurityGroup: {security_group_id}')
                return True
            self.logger.error(f'API call to authorize the security group {security_group_id} has failed.\n{error}')
            return False
        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'Ingress Successfully Set for SecurityGroup {security_group_id}')
            for sg_rule in response['SecurityGroupRules']:
                log = 'Allowed protocol: ' + sg_rule['IpProtocol'] + ' '
                if sg_rule['FromPort'] == sg_rule['ToPort']:
                    log += 'on port: ' + str(sg_rule['ToPort']) + ' '
                else:
                    log += 'from port:  ' f"{sg_rule['FromPort']} to port: {sg_rule['ToPort']}" + ' '
                self.logger.info(log + 'with CIDR ' + sg_rule['CidrIpv4'])
            return True
        else:
            self.logger.info(f'Failed to set Ingress: {response}')

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
                GroupName=self.security_group_name,
                Description='Security Group to allow certain port ranges for VM.',
                VpcId=vpc_id
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidGroup.Duplicate)' in error and self.security_group_name in error:
                self.logger.warning(f'Found an existing SecurityGroup named: {self.security_group_name}. Reusing it.')
                response = self.ec2_client.describe_security_groups(
                    Filters=[
                        dict(Name='group-name', Values=[self.security_group_name])
                    ]
                )
                group_id = response['SecurityGroups'][0]['GroupId']
                return group_id
            self.logger.error(f'API call to create security group has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            security_group_id = response['GroupId']
            self.logger.info(f'Security Group Created {security_group_id} in VPC {vpc_id}')
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
                KeyName=self.key_name,
                SecurityGroupIds=[security_group_id]
            )
        except ClientError as error:
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            self.logger.error(f'API call to create instance has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            instance_id = response.get('Instances')[0].get('InstanceId')
            self.logger.info(f'Created the EC2 instance: {instance_id}')
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
                KeyName=self.key_name
            )
        except ClientError as error:
            self.logger.error(f'API call to delete the key {self.key_name} has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'{self.key_name} has been deleted from KeyPairs.')
            if path.exists(f'{self.key_name}.pem'):
                system(f'chmod 700 {self.key_name}.pem')  # reset file permissions before deleting
                remove(f'{self.key_name}.pem')
            return True
        else:
            self.logger.error(f'Failed to delete the key: {self.key_name}')

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
            self.logger.error(f'API call to delete the Security Group {security_group_id} has failed.\n{error}')
            if '(InvalidGroup.NotFound)' in str(error):
                return True
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'{security_group_id} has been deleted from Security Groups.')
            return True
        else:
            self.logger.error(f'Failed to delete the SecurityGroup: {security_group_id}')

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
            self.logger.error(f'API call to terminate the instance has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'InstanceId {instance_id} has been set to terminate.')
            return True
        else:
            self.logger.error(f'Failed to terminate the InstanceId: {instance_id}')

    def _instance_info(self, instance_id: str) -> tuple or None:
        """Makes a ``describe_instance_status`` API call to get the status of the instance that was created.

        Args:
            instance_id: Takes the instance ID as an argument.

        Returns:
            tuple or None:
            A tuple object of Public DNS Name and Public IP Address.
        """
        self.logger.info('Waiting for the instance to go live.')
        sleeper(sleep_time=25)
        while True:
            sleeper(sleep_time=5)
            try:
                response = self.ec2_client.describe_instance_status(
                    InstanceIds=[instance_id]
                )
            except ClientError as error:
                self.logger.error(f'API call to describe instance has failed.{error}')
                return

            if response.get('ResponseMetadata').get('HTTPStatusCode') != 200:
                continue
            if status := response.get('InstanceStatuses'):
                if status[0].get('InstanceState').get('Name') == 'running':
                    instance_info = self.ec2_resource.Instance(instance_id)
                    return instance_info.public_dns_name, instance_info.public_ip_address

    def _optional_args(self) -> bool:
        """Checks for the optional arguments/env vars.

        Returns:
            bool:
            A boolean flag to indicate whether the necessary args are present before startup.
        """
        if not any([self.domain_name, self.subdomain, self.email_address, self.organization]):
            return False
        return True

    def start(self) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the ec2 instance."""
        if path.isfile(self.server_file) and path.isfile(f'{self.key_name}.pem'):
            self.logger.warning('Received request to start VM, but looks like a session is up and running already.')
            self.logger.warning('Initiating re-configuration.')
            sleeper(sleep_time=10)
            with open(self.server_file, 'r') as file:
                data = json.load(file)
            self._configure_vm(public_dns=data.get('public_dns'), public_ip=data.get('public_ip'))
            return

        if not self.port:
            self.logger.error('Port number is mandatory to initiate tunneling. Received `null`')
            self.logger.error('Check https://github.com/thevickypedia/expose#environment-variables for more information'
                              ' on setting up env vars.')
            return

        if not self.image_id:
            self._get_image_id()
            self.logger.warning(f"AMI ID was not set."
                                f"Using the default AMI ID {self.image_id} for the region {self.region}")

        if not self._optional_args():
            self.logger.warning('DOMAIN, SUBDOMAIN, EMAIL and ORG gives a customized access to the tunnel.')

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
            'ssh_endpoint': f'ssh -i {self.key_name}.pem ubuntu@{public_dns}',
            'start_tunneling': f"ssh -i {self.key_name}.pem -R 8080:localhost:{self.port} ubuntu@{public_dns}"
        }

        self.logger.info(f'Restricting wide open permissions to {self.key_name}.pem')
        system(f'chmod 400 {self.key_name}.pem')

        with open(self.server_file, 'w') as file:
            json.dump(instance_info, file, indent=2)

        self.logger.info('Waiting for SSH origin to be active.')
        sleeper(sleep_time=15)

        self._configure_vm(public_dns=public_dns, public_ip=public_ip)

    def _configure_vm(self, public_dns: str, public_ip: str):
        """Configures the ec2 instance to take traffic from localhost.

        Args:
            public_dns: Public DNS name of the EC2 that was created.
            public_ip: Public IP of the EC2 that was created.
        """
        self.logger.info('Gathering pieces for configuration.')
        custom_servers = f"{public_dns} {public_ip}"

        endpoint, email = None, None
        if self.domain_name and self.subdomain:
            if self.subdomain.endswith(self.domain_name):
                endpoint = self.subdomain
                custom_servers += f' {self.subdomain}'
            else:
                endpoint = f'{self.subdomain}.{self.domain_name}'
                custom_servers += f' {self.subdomain}.{self.domain_name}'
            if git_email := check_output('git config user.email', shell=True):
                email = git_email.decode('UTF-8').strip()

        for conf_file in CONFIGURATION_FILES:
            download_file = conf_file.removeprefix(CURRENT_DIR)
            self.logger.info(f'Downloading the configuration file: {download_file}.')
            response = requests.get(url=f'{CONFIGURATION_LOCATION}{download_file}')
            if not response.ok:
                raise ConnectionError(f'Failed to download the config file: {download_file}')
            with open(conf_file, 'w') as file:
                file.write(response.text.replace('SERVER_NAME_HERE', custom_servers))

        copy_files = [f"{CURRENT_DIR}server.conf", f"{CURRENT_DIR}nginx.conf"]
        if path.isdir(f"{HOME_DIR}.ssh") and \
                path.isfile(f"{HOME_DIR}.ssh{SEP}key.pem") and \
                path.isfile(f"{HOME_DIR}.ssh{SEP}cert.pem"):
            self.logger.info(f'Found certificate and key in {HOME_DIR}')
            secured = True
            copy_files.extend([f"{HOME_DIR}.ssh{SEP}cert.pem", f"{HOME_DIR}.ssh{SEP}key.pem",
                               f"{CURRENT_DIR}options-ssl-nginx.conf"])
            rename(src=f"{CURRENT_DIR}nginx-ssl.conf", dst=f"{CURRENT_DIR}nginx.conf")
        elif path.isfile(f'{CURRENT_DIR}cert.pem') and path.isfile(f'{CURRENT_DIR}key.pem'):
            self.logger.info(f'Found certificate and key in {path}')
            secured = True
            copy_files.extend([f"{CURRENT_DIR}cert.pem", f"{CURRENT_DIR}key.pem",
                               f"{CURRENT_DIR}options-ssl-nginx.conf"])
            rename(src=f"{CURRENT_DIR}nginx-ssl.conf", dst=f"{CURRENT_DIR}nginx.conf")
        elif generate_cert(common_name=endpoint or public_dns, email_address=self.email_address or email,
                           organization_name=self.organization):
            self.logger.info('Generated self-signed SSL certificate and private key.')
            secured = True
            CONFIGURATION_FILES.extend([f'{CURRENT_DIR}cert.pem', f'{CURRENT_DIR}key.pem'])
            copy_files.extend([f"{CURRENT_DIR}cert.pem", f"{CURRENT_DIR}key.pem",
                               f"{CURRENT_DIR}options-ssl-nginx.conf"])
            rename(src=f"{CURRENT_DIR}nginx-ssl.conf", dst=f"{CURRENT_DIR}nginx.conf")
        else:
            self.logger.warning('Failed to generate self-signed SSL certificate and private key.')
            secured = False
            rename(src=f"{CURRENT_DIR}nginx-non-ssl.conf", dst=f"{CURRENT_DIR}nginx.conf")

        nginx_server = ServerConfig(hostname=public_dns, pem_file=f'{self.key_name}.pem')
        nginx_server.server_copy(files=copy_files)
        self.logger.info(f'Copied required files to {public_dns}')

        CONFIGURATION_FILES.extend([f'{CURRENT_DIR}nginx.conf'])
        for file in CONFIGURATION_FILES:
            if path.isfile(file):
                self.logger.info(f'Removing {file}')
                remove(file)

        self.logger.info('Configuring nginx server.')
        nginx_status = nginx_server.run_interactive_ssh(
            commands={
                "sudo apt-get update -y": 5,
                "sudo apt-get upgrade -y": 5,
                "echo Y | sudo -S apt-get install nginx -y": 10,
                "sudo mv /home/ubuntu/server.conf /etc/nginx/conf.d/server.conf": 1,
                "sudo mv /home/ubuntu/nginx.conf /etc/nginx/nginx.conf": 1,
                "sudo systemctl restart nginx": 2
            }
        )
        if not nginx_status:
            self.logger.error('Nginx server was not configured. Cleaning up AWS resources acquired.')
            self.stop()
            return

        self.logger.info('Nginx server was configured successfully.')
        protocol = 'https' if secured else 'http'
        if endpoint:
            change_record_set(dns_name=self.domain_name, source=self.subdomain, destination=public_ip, record_type='A')
            self.logger.info(f'{protocol}://{endpoint} → http://localhost:{self.port}')
        else:
            self.logger.info(f'{protocol}://{public_dns} → http://localhost:{self.port}')

        self.logger.info('Initiating tunnel')
        system(
            f"ssh -o StrictHostKeyChecking=no -i {self.key_name}.pem -R 8080:localhost:{self.port} ubuntu@{public_dns}"
        )

    def stop(self) -> None:
        """Disables tunnelling by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created."""
        if not path.exists(self.server_file):
            self.logger.info(f'Input file: {self.server_file} is missing. CANNOT proceed.')
            return

        with open(self.server_file, 'r') as file:
            data = json.load(file)

        if self._delete_key_pair() and self._terminate_ec2_instance(instance_id=data.get('instance_id')):
            if (domain_name := self.domain_name) and (subdomain := self.subdomain):
                change_record_set(dns_name=domain_name, source=subdomain, destination=data.get('public_ip'),
                                  record_type='A', action='DELETE')
            self.logger.info('Waiting for dependent objects to delete SecurityGroup.')
            sleeper(sleep_time=90)
            while True:
                if self._delete_security_group(security_group_id=data.get('security_group_id')):
                    break
                else:
                    sleeper(sleep_time=20)
            remove(self.server_file)
