import json
import logging
import os
import time
import warnings
from typing import Tuple

import boto3
import inflect
import urllib3.exceptions
from boto3.resources.base import ServiceResource
from botocore.exceptions import ClientError, WaiterError

from expose.helpers.auxiliary import IP_INFO, NotImplementedWarning
from expose.helpers.cert import generate_cert
from expose.helpers.config import EnvConfig, settings
from expose.helpers.defaults import AWSDefaults
from expose.helpers.logger import LOGGER
from expose.helpers.route_53 import change_record_set
from expose.helpers.server import Server

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable warnings for self-signed certificates


class Tunnel:
    """Initiates ``Tunnel`` object to spin up an EC2 instance with a pre-configured AMI which acts as a tunnel.

    >>> Tunnel

    """

    def __init__(self,
                 port: int = None,
                 image_id: str = None,
                 domain: str = None,
                 subdomain: str = None,
                 aws_access_key: str = None,
                 aws_secret_key: str = None,
                 aws_region_name: str = None,
                 email_address: str = None,
                 organization: str = None,
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
        self.nginx_server = None

    def get_image_id(self) -> None:
        """Fetches AMI ID from public images."""
        if self.region.startswith('us'):
            self.image_id = AWSDefaults.IMAGE_MAP[self.region]
            return

        try:
            images = list(self.ec2_resource.images.filter(
                Filters=[{'Name': 'name', 'Values': [AWSDefaults.DEFAULT_AMI_NAME]}]
            ))
        except ClientError as error:
            self.logger.warning('API call to retrieve AMI ID for %s has failed.', self.region)
            self.logger.error(error)
            raise

        if not images:
            raise LookupError(f'Failed to retrieve AMI ID for {self.region}. Set one manually.')
        self.image_id = images[0].id

    def create_key_pair(self) -> bool:
        """Creates a ``KeyPair`` of type ``RSA`` stored as a ``PEM`` file to use with ``OpenSSH``.

        Returns:
            bool:
            Flag to indicate the calling function if a ``KeyPair`` was created.
        """
        try:
            key_pair = self.ec2_resource.create_key_pair(
                KeyName=settings.key_pair_name,
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            # todo: Fail on duplicate
            if '(InvalidKeyPair.Duplicate)' in error:
                self.logger.warning('Found an existing KeyPair named: %s. Re-creating it.',
                                    settings.key_pair_name)
                self.delete_key_pair()
                return self.create_key_pair()
            self.logger.warning('API call to create key pair has failed.')
            self.logger.error(error)
            return False

        with open(f'{settings.key_pair_name}.pem', 'w') as file:
            file.write(key_pair.key_material)
            file.flush()
        self.logger.info('Stored KeyPair as %s', settings.key_pair_name)
        return True

    def get_vpc_id(self) -> str or None:
        """Gets the default VPC id.

        Returns:
            str or None:
            Default VPC id.
        """
        try:
            vpcs = list(self.ec2_resource.vpcs.all())
        except ClientError as error:
            self.logger.warning('API call to get VPC ID has failed.')
            self.logger.error(error)
            return None
        default_vpc = None
        for vpc in vpcs:
            if vpc.is_default:
                default_vpc = vpc
                break
        if default_vpc:
            self.logger.info('Got the default VPC: %s', default_vpc.id)
            return default_vpc.id
        else:
            self.logger.error('Unable to get the default VPC ID')

    def authorize_security_group(self,
                                 security_group_id: str,
                                 public_ip: str) -> bool:
        """Authorizes the security group for certain ingress list.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.
            public_ip: Public IP address of the ec2 instance.

        Returns:
            bool:
            Flag to indicate the calling function whether the security group was authorized.
        """
        try:
            security_group = self.ec2_resource.SecurityGroup(security_group_id)
            security_group.authorize_ingress(
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
                     'FromPort': self.port,
                     'ToPort': self.port,
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
            self.logger.error('API call to authorize the security group %s has failed.', security_group_id)
            self.logger.error(error)
            return False
        for sg_rule in security_group.ip_permissions:
            log = 'Allowed protocol: ' + sg_rule['IpProtocol'] + ' '
            if sg_rule['FromPort'] == sg_rule['ToPort']:
                log += 'on port: ' + str(sg_rule['ToPort']) + ' '
            else:
                log += 'from port: ' f"{sg_rule['FromPort']} to port: {sg_rule['ToPort']}" + ' '
            for ip_range in sg_rule['IpRanges']:
                self.logger.info(log + 'with CIDR ' + ip_range['CidrIp'])
        return True

    def create_security_group(self) -> str or None:
        """Calls the class method ``_get_vpc_id`` and uses the VPC ID to create a ``SecurityGroup`` for the instance.

        Returns:
            str or None:
            SecurityGroup ID
        """
        if not (vpc_id := self.get_vpc_id()):
            return

        try:
            security_group = self.ec2_resource.create_security_group(
                GroupName=settings.security_group_name,
                Description='Security Group to allow certain port ranges for exposing localhost to public internet.',
                VpcId=vpc_id
            )
        except ClientError as error:
            error = str(error)
            # todo: fail on duplicate
            if '(InvalidGroup.Duplicate)' in error and settings.security_group_name in error:
                security_groups = list(self.ec2_resource.security_groups.all())
                for security_group in security_groups:
                    if security_group.group_name == settings.security_group_name:
                        self.logger.info("Re-using existing SecurityGroup '%s'", security_group.group_id)
                        return security_group.group_id
                raise RuntimeError('Duplicate raised, but no such SG found.')
            self.logger.warning('API call to create security group has failed.')
            self.logger.error(error)
            return

        security_group_id = security_group.id
        self.logger.info('Security Group created %s in VPC %s', security_group_id, vpc_id)
        return security_group_id

    def create_ec2_instance(self) -> Tuple[str, str] or None:
        """Creates an EC2 instance of type ``t2.nano`` with the pre-configured AMI id.

        Returns:
            Tuple[str, str, str, str]:
            Instance ID, SecurityGroup ID, Public DNS name, Public IP address
        """
        if not (security_group_id := self.create_security_group()):
            self.delete_key_pair()
            return
        if not self.create_key_pair():
            return
        try:
            # Use the EC2 resource to launch an EC2 instance
            instances = self.ec2_resource.create_instances(
                ImageId=self.image_id,
                MinCount=1,
                MaxCount=1,
                InstanceType="t2.nano",
                KeyName=settings.key_pair_name,
                SecurityGroupIds=[security_group_id]
            )
            instance = instances[0]  # Get the first (and only) instance
        except ClientError as error:
            self.delete_key_pair()
            self.delete_security_group(security_group_id=security_group_id)
            self.logger.warning('API call to create instance has failed.')
            self.logger.error(error)
            return None

        instance_id = instance.id
        self.logger.info('Created the EC2 instance: %s', instance_id)
        return instance_id, security_group_id

    def delete_key_pair(self) -> bool:
        """Deletes the ``KeyPair``.

        Returns:
            bool:
            Flag to indicate the calling function if the KeyPair was deleted.
        """
        try:
            key_pair = self.ec2_resource.KeyPair(settings.key_pair_name)
            key_pair.delete()
        except ClientError as error:
            self.logger.warning("API call to delete the key '%s' has failed.", settings.key_pair_name)
            self.logger.error(error)
            return False

        self.logger.info('%s has been deleted from KeyPairs.', settings.key_pair_name)

        # Delete the associated .pem file if it exists
        if os.path.exists(settings.key_pair_file):
            os.chmod(settings.key_pair_file, int('700', base=8) or 0o700)
            os.remove(settings.key_pair_file)
            self.logger.info(f'Removed {settings.key_pair_file}.')
            return True

    # noinspection PyUnresolvedReferences
    def disassociate_security_group(self,
                                    security_group_id: str,
                                    instance: ServiceResource = None,
                                    instance_id: str = None) -> bool:
        """Disassociate a security group from the instance.

        Args:
            security_group_id: Security group ID
            instance: Instance object.
            instance_id: Instance ID if object is unavailable.

        Returns:
            bool:
            Boolean value based on disassociation result.
        """
        try:
            if not instance:
                instance = self.ec2_resource.Instance(instance_id)
            if security_groups := list(self.ec2_resource.security_groups.filter(GroupNames=['default'])):
                default_sg = security_groups[0]
                instance.modify_attribute(Groups=[default_sg.id])
                instance.modify_attribute(Groups=[group_id['GroupId'] for group_id in instance.security_groups
                                                  if group_id['GroupId'] != security_group_id])
                self.logger.info("Security group %s has been disassociated from instance %s.",
                                 security_group_id, instance.id)
                return True
            else:
                self.logger.info("Unable to get default SG to replace association")
        except ClientError as error:
            self.logger.info(error)

    def delete_security_group(self,
                              security_group_id: str) -> bool:
        """Deletes the security group.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        Returns:
            bool:
            Flag to indicate the calling function whether the SecurityGroup was deleted.
        """
        try:
            security_group = self.ec2_resource.SecurityGroup(security_group_id)
            security_group.delete()
        except ClientError as error:
            self.logger.warning('API call to delete the Security Group %s has failed.', security_group_id)
            self.logger.error(error)
            if '(InvalidGroup.NotFound)' in str(error):
                return True
            return False
        self.logger.info('%s has been deleted from Security Groups.', security_group_id)
        return True

    def terminate_ec2_instance(self,
                               instance_id: str = None,
                               instance: object = None) -> ServiceResource or None:
        """Terminates the requested instance.

        Args:
            instance_id: Takes instance ID as an argument. Defaults to the instance that was created previously.
            instance: Takes the instance object as an optional argument.

        Returns:
            bool:
            Flag to indicate the calling function whether the instance was terminated.
        """
        assert instance or instance_id, "Both instance object and instance_id cannot be None"  # todo: remove assert
        try:
            if not instance:
                instance = self.ec2_resource.Instance(instance_id)
            if not instance_id:
                instance_id = instance.id
            instance.terminate()
        except ClientError as error:
            self.logger.warning('API call to terminate the instance has failed.')
            self.logger.error(error)
            return
        self.logger.info('InstanceId %s has been set to terminate.', instance_id)
        return instance

    def start(self,
              purge: bool = False) -> None:
        """Starts an ec2 instances, and initiates VM configuration.

        Args:
            purge: Boolean flag to delete all AWS resource if initial configuration fails.

        See Also:
            Automatic purge works only during initial setup, and not during re-configuration.

        References:
            https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-status.html#options
        """
        try:
            self.port = int(self.port)
        except (TypeError, ValueError):
            self.logger.error("Port number is mandatory and should be an integer to initiate tunneling. "
                              "Received '%s'", self.port)
            return

        if os.path.isfile(settings.server_info) and os.path.isfile(settings.key_pair_file):
            self.logger.warning('Received request to start VM, but looks like a session is up and running already.')
            self.logger.warning('Initiating re-configuration.')
            with open(settings.server_info) as file:
                data = json.load(file)
            self.configure_vm(public_dns=data.get('public_dns'), public_ip=data.get('public_ip'))
            return

        if not all((self.domain_name, self.subdomain)):
            self.logger.warning("DOMAIN and SUBDOMAIN gives a customized access to the tunnel.")
        if not all((self.email_address, self.organization)):
            self.logger.warning("EMAIL_ADDRESS and ORGANIZATION can be used to create a customized certificate.")

        if not self.image_id:
            self.get_image_id()
            self.logger.info("AMI ID was not set. Using the default AMI ID '%s' for the region '%s'",
                             self.image_id, self.region)

        if ec2_info := self.create_ec2_instance():
            instance_id, security_group_id = ec2_info
        else:
            return

        instance = self.ec2_resource.Instance(instance_id)
        self.logger.info("Waiting for instance to enter 'running' state")
        try:
            instance.wait_until_running(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        except WaiterError as error:
            self.logger.error(error)
            warnings.warn(
                "Failed on waiting for instance to enter 'running' state, please raise an issue at:\n"
                "https://github.com/thevickypedia/expose/issues",
                NotImplementedWarning
            )
            self.logger.warning("SecurityGroup will not be deleted automatically.")
            if purge:
                self.delete_key_pair()
                self.terminate_ec2_instance(instance=instance)
                return
        instance.reload()
        self.logger.info("Finished re-loading instance '%s'", instance_id)

        if not self.authorize_security_group(security_group_id, instance.public_ip_address):
            self.delete_key_pair()
            sg_association = self.disassociate_security_group(instance=instance, security_group_id=security_group_id)
            self.terminate_ec2_instance(instance=instance)
            if not sg_association:
                try:
                    instance.wait_until_terminated()  # todo: setup filters
                except WaiterError as error:
                    self.logger.error(error)
                    warnings.warn(
                        "Failed on waiting for instance to enter 'running' state, please raise an issue at:\n"
                        "https://github.com/thevickypedia/expose/issues",
                        NotImplementedWarning
                    )
            self.delete_security_group(security_group_id)
            return

        instance_info = {
            'port': self.port,
            'instance_id': instance_id,
            'public_dns': instance.public_dns_name,
            'public_ip': instance.public_ip_address,
            'security_group_id': security_group_id,
            'ssh_endpoint': f'ssh -i {settings.key_pair_file} ubuntu@{instance.public_dns_name}',
            'start_tunneling':
                f"ssh -i {settings.key_pair_file} -R 8080:localhost:{self.port} ubuntu@{instance.public_dns_name}"
        }

        os.chmod(settings.key_pair_file, int('400', base=8) or 0o400)

        with open(settings.server_info, 'w') as file:
            json.dump(instance_info, file, indent=2)
            file.flush()

        self.logger.info('Waiting for SSH origin to be active.')
        instance.reload()
        self.logger.info('Finished re-loading')
        self.configure_vm(public_dns=instance.public_dns_name, public_ip=instance.public_ip_address, disposal=purge)

    def server_copy(self, source: str, destination: str) -> None:
        """Reads a file in localhost and writes it within SSH connection.

        Args:
            source: Name of the source file in localhost.
            destination: Name of the destination file in the server.
        """
        self.logger.info("Copying '%s' to SSH server as '%s'", source, destination)
        with open(source) as f:
            self.nginx_server.server_write(data={destination: f.read()})

    def get_config(self, filename: str, server: str):
        """Downloads configuration files from GitHub.

        Args:
            filename: Name of the file that has to be downloaded.
            server: Custom server names to be added in configuration files.

        Returns:
            str:
            Returns the data of the file as a string.
        """
        self.logger.info('Loading the configuration file: %s.', filename)
        with open(os.path.join(settings.configuration, filename)) as file:
            return file.read().\
                replace('SERVER_NAME_HERE', server).\
                replace('SSH_PATH_HERE', settings.ssh_home).\
                replace('CERTIFICATE_HERE', f'{settings.ssh_home}/{settings.cert_file}').\
                replace('PRIVATE_KEY_HERE', f'{settings.ssh_home}/{settings.key_file}')

    def configure_vm(self,
                     public_dns: str,
                     public_ip: str,
                     disposal: bool = False):
        """Configures the ec2 instance to take traffic from localhost.

        Args:
            public_dns: Public DNS name of the EC2 that was created.
            public_ip: Public IP of the EC2 that was created.
            disposal: Boolean flag to delete all AWS resources on failed configuration.
        """
        self.logger.info('Gathering configuration requirements.')
        custom_servers = f"{public_dns} {public_ip}"

        endpoint = None
        if self.domain_name and self.subdomain:
            if self.subdomain.endswith(self.domain_name):
                endpoint = self.subdomain
                custom_servers += f' {self.subdomain}'
            else:
                endpoint = f'{self.subdomain}.{self.domain_name}'
                custom_servers += f' {self.subdomain}.{self.domain_name}'

        for i in range(10):
            try:
                self.nginx_server = Server(hostname=public_dns, pem_file=settings.key_pair_file, logger=self.logger)
                self.logger.info("Connection established in %s attempt", inflect.engine().ordinal(i+1))
                break
            except Exception as error:
                self.logger.error(type(error))  # todo: remove
                self.logger.error(error)
                time.sleep(3)
        else:
            self.stop()
            raise TimeoutError(
                "Unable to connect SSH server"
            )

        load_and_copy = {"server.conf": self.get_config(filename="server.conf", server=custom_servers)}
        if os.path.isfile(os.path.join(settings.current_dir, settings.cert_file)) and \
                os.path.isfile(os.path.join(settings.current_dir, settings.key_file)):
            self.logger.info('Found certificate and key in %s', settings.current_dir)
            self.server_copy(source=os.path.join(settings.current_dir, settings.cert_file),
                             destination=settings.cert_file)
            self.server_copy(source=os.path.join(settings.current_dir, settings.key_file),
                             destination=settings.key_file)
            load_and_copy["options-ssl-nginx.conf"] = self.get_config(filename="options-ssl-nginx.conf",
                                                                      server=custom_servers)
            load_and_copy["nginx.conf"] = self.get_config(filename="nginx-ssl.conf", server=custom_servers)
        elif generate_cert(common_name=endpoint or public_dns, email_address=self.email_address,
                           organization_name=self.organization, cert_file=settings.cert_file,
                           key_file=settings.key_file):
            self.logger.info('Generated self-signed SSL certificate and private key.')
            self.server_copy(source=os.path.join(settings.current_dir, settings.cert_file),
                             destination=settings.cert_file)
            self.server_copy(source=os.path.join(settings.current_dir, settings.key_file),
                             destination=settings.key_file)
            load_and_copy["options-ssl-nginx.conf"] = self.get_config(filename="options-ssl-nginx.conf",
                                                                      server=custom_servers)
            load_and_copy["nginx.conf"] = self.get_config(filename="nginx-ssl.conf", server=custom_servers)
        else:
            self.logger.warning('Failed to generate self-signed SSL certificate and private key.')
            load_and_copy["nginx.conf"] = self.get_config(filename="nginx-non-ssl.conf", server=custom_servers)

        self.logger.info('Copying configuration files to %s', public_dns)
        self.nginx_server.server_write(data=load_and_copy)

        self.logger.info('Configuring nginx server.')
        nginx_status = self.nginx_server.run_interactive_ssh(
            commands=(
                "sudo apt-get update -y",
                "echo Y | sudo -S apt-get install nginx -y",
                "sudo mv /home/ubuntu/nginx.conf /etc/nginx/nginx.conf",
                "sudo mv /home/ubuntu/server.conf /etc/nginx/conf.d/server.conf",
                "sudo systemctl restart nginx"
            )
        )
        if nginx_status:
            self.logger.info('Nginx server was configured successfully.')
        else:
            self.logger.error('Nginx server was not configured.')
            if disposal:
                self.logger.info('Cleaning up AWS resources acquired.')
                self.stop()
            return

        protocol = 'https' if load_and_copy.get("options-ssl-nginx.conf") else 'http'
        if endpoint:
            change_record_set(dns_name=self.domain_name, source=self.subdomain, destination=public_ip, record_type='A',
                              logger=self.logger, client=self.route53_client)
            self.logger.info('%s://%s -> http://localhost:%d', protocol, endpoint, self.port)
        else:
            self.logger.info('%s://%s -> http://localhost:%d', protocol, public_dns, self.port)

        self.logger.info('Initiating tunnel')
        self.nginx_server.initiate_tunnel(port=self.port)

    def stop(self, instance_id: str = None, security_group_id: str = None) -> None:
        """Disables tunnelling by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        Args:
            instance_id: Instance that has to be terminated.
            security_group_id: Security group that has to be removed.
        """
        if not os.path.exists(settings.server_info) and not instance_id and not security_group_id:
            self.logger.info('Input file: server_info.json is missing. CANNOT proceed.')
            return

        with open(settings.server_info) as file:
            data = json.load(file)

        security_group_id = security_group_id or data.get('security_group_id')
        instance_id = instance_id or data.get('instance_id')

        self.delete_key_pair()
        sg_association = self.disassociate_security_group(instance_id=instance_id, security_group_id=security_group_id)
        instance = self.terminate_ec2_instance(instance_id=instance_id)
        if self.domain_name and self.subdomain:
            change_record_set(dns_name=self.domain_name, source=self.subdomain, destination=data.get('public_ip'),
                              record_type='A', action='DELETE', logger=self.logger, client=self.route53_client)
        if not sg_association and instance:
            try:
                instance.wait_until_terminated()  # todo: setup filters for wait until terminated
            except WaiterError as error:
                self.logger.error(error)
        self.delete_security_group(security_group_id)
        os.remove(settings.server_info) if os.path.isfile(settings.server_info) else None
