import json
import logging
import os
import time
import warnings
from typing import Dict, Tuple

import boto3
import inflect
import urllib3.exceptions
from boto3.resources.base import ServiceResource
from botocore.exceptions import ClientError, WaiterError

from expose.helpers.auxiliary import IP_INFO
from expose.helpers.cert import generate_cert
from expose.helpers.config import env, settings
from expose.helpers.defaults import AWSDefaults
from expose.helpers.logger import LOGGER
from expose.helpers.route_53 import change_record_set
from expose.helpers.server import Server
from expose.helpers.warnings import NotImplementedWarning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable warnings for self-signed certificates


class Tunnel:
    """Initiates ``Tunnel`` object to spin up an EC2 instance with a pre-configured AMI which acts as a tunnel.

    >>> Tunnel

    """

    def __init__(self, logger: logging.Logger = None):
        """Instantiates all required AWS resources."""
        # AWS client and resource setup
        session = boto3.Session(region_name=env.aws_region_name,
                                aws_access_key_id=env.aws_access_key,
                                aws_secret_access_key=env.aws_secret_key)
        self.ec2_resource = session.resource(service_name='ec2')
        self.route53_client = session.client(service_name='route53')

        # Tunnelling requirements setup
        self.logger = logger or LOGGER
        self.nginx_server = None
        self.image_id = None

    def get_image_id(self) -> None:
        """Fetches AMI ID from public images."""
        if env.aws_region_name.startswith('us'):
            self.image_id = AWSDefaults.IMAGE_MAP[env.aws_region_name]
            return

        try:
            images = list(self.ec2_resource.images.filter(
                Filters=[{'Name': 'name', 'Values': [AWSDefaults.DEFAULT_AMI_NAME]}]
            ))
        except ClientError as error:
            self.logger.warning('API call to retrieve AMI ID for %s has failed.', env.aws_region_name)
            self.logger.error(error)
            raise

        if not images:
            raise LookupError(f'Failed to retrieve AMI ID for {env.aws_region_name}. Set one manually.')
        self.image_id = images[0].id

    def create_key_pair(self) -> bool:
        """Creates a ``KeyPair`` of type ``RSA`` stored as a ``PEM`` file to use with ``OpenSSH``.

        Returns:
            bool:
            Flag to indicate the calling function if a ``KeyPair`` was created.
        """
        try:
            key_pair = self.ec2_resource.create_key_pair(
                KeyName=env.key_pair,
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            # todo: Fail on duplicate
            if '(InvalidKeyPair.Duplicate)' in error:
                self.logger.warning('Found an existing KeyPair named: %s. Re-creating it.',
                                    env.key_pair)
                self.delete_key_pair()
                return self.create_key_pair()
            self.logger.warning('API call to create key pair has failed.')
            self.logger.error(error)
            return False

        with open(settings.key_pair_file, 'w') as file:
            file.write(key_pair.key_material)
            file.flush()
        self.logger.info('Stored KeyPair as %s', settings.key_pair_file)
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
                     'FromPort': env.port,
                     'ToPort': env.port,
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
                GroupName=env.security_group,
                Description='Security Group to allow certain port ranges for exposing localhost to public internet.',
                VpcId=vpc_id
            )
        except ClientError as error:
            error = str(error)
            # todo: fail on duplicate
            if '(InvalidGroup.Duplicate)' in error and env.security_group in error:
                security_groups = list(self.ec2_resource.security_groups.all())
                for security_group in security_groups:
                    if security_group.group_name == env.security_group:
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
                KeyName=env.key_pair,
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
            key_pair = self.ec2_resource.KeyPair(env.key_pair)
            key_pair.delete()
        except ClientError as error:
            self.logger.warning("API call to delete the key '%s' has failed.", env.key_pair)
            self.logger.error(error)
            return False

        self.logger.info('%s has been deleted from KeyPairs.', env.key_pair)

        # Delete the associated .pem file if it exists
        if os.path.exists(settings.key_pair_file):
            os.chmod(settings.key_pair_file, int('700', base=8) or 0o700)
            os.remove(settings.key_pair_file)
            self.logger.info(f'Removed {settings.key_pair_file}.')
            return True

    def disassociate_security_group(self,
                                    security_group_id: str,
                                    instance: object = None,
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

    def delete_security_group(self, security_group_id: str) -> bool:
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

    def start(self, purge: bool = False) -> None:
        """Starts an ec2 instances, and initiates VM configuration.

        Args:
            purge: Boolean flag to delete all AWS resource if initial configuration fails.

        See Also:
            Automatic purge works only during initial setup, and not during re-configuration.

        References:
            https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-status.html#options
        """
        if os.path.isfile(env.server_info) and os.path.isfile(settings.key_pair_file):
            self.logger.warning('Received request to start VM, but looks like a session is up and running already.')
            self.logger.warning('Initiating re-configuration.')
            with open(env.server_info) as file:
                data = json.load(file)
            self.configure_vm(public_dns=data.get('public_dns'), public_ip=data.get('public_ip'))
            return

        if not all((env.domain, env.subdomain)):
            self.logger.warning("DOMAIN and SUBDOMAIN gives a customized access to the tunnel.")

        if not self.image_id:
            self.get_image_id()
            self.logger.info("AMI ID was not set. Using the default AMI ID '%s' for the region '%s'",
                             self.image_id, env.aws_region_name)

        if ec2_info := self.create_ec2_instance():
            instance_id, security_group_id = ec2_info
        else:
            return

        instance = self.ec2_resource.Instance(instance_id)
        self.logger.info("Waiting for instance to enter 'running' state")
        try:
            instance.wait_until_running(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )
        except WaiterError as error:
            self.logger.error(error)
            warnings.warn(
                "Failed on waiting for instance to enter 'running' state, please raise an issue at:\n"
                "https://github.com/thevickypedia/expose/issues",
                NotImplementedWarning
            )
            self.delete_key_pair()
            self.disassociate_security_group(instance=instance, security_group_id=security_group_id)
            self.terminate_ec2_instance(instance=instance)
            self.delete_security_group(security_group_id)
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
            'port': env.port,
            'instance_id': instance_id,
            'public_dns': instance.public_dns_name,
            'public_ip': instance.public_ip_address,
            'security_group_id': security_group_id,
            'ssh_endpoint': f'ssh -i {settings.key_pair_file} ubuntu@{instance.public_dns_name}',
            'start_tunneling':
                f"ssh -i {settings.key_pair_file} -R 8080:localhost:{env.port} ubuntu@{instance.public_dns_name}"
        }

        os.chmod(settings.key_pair_file, int('400', base=8) or 0o400)

        with open(env.server_info, 'w') as file:
            json.dump(instance_info, file, indent=2)
            file.flush()

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
                replace('CERTIFICATE_HERE', f'{settings.ssh_home}/{env.cert_file}').\
                replace('PRIVATE_KEY_HERE', f'{settings.ssh_home}/{env.key_file}')

    def config_requirements(self, common_name: str, custom_servers: str) -> Dict[str, str]:
        """Tries to create a self-signed SSL certificate and loads all the required configuration into a dictionary.

        Args:
            common_name: DNS entry for SSL creation.
            custom_servers: Server names to be loaded in the nginx config files.

        Returns:
            Dict[str, str]:
            Dictionary of config file name and the configuration data.
        """
        config_data = {"server.conf": self.get_config("server.conf", custom_servers)}
        if os.path.isfile(os.path.join(settings.current_dir, env.cert_file)) and \
                os.path.isfile(os.path.join(settings.current_dir, env.key_file)):
            self.logger.info('Found certificate and key in %s', settings.current_dir)
            self.server_copy(source=os.path.join(settings.current_dir, env.cert_file), destination=env.cert_file)
            self.server_copy(source=os.path.join(settings.current_dir, env.key_file), destination=env.key_file)
            config_data["options-ssl-nginx.conf"] = self.get_config("options-ssl-nginx.conf", custom_servers)
            config_data["nginx.conf"] = self.get_config("nginx-ssl.conf", custom_servers)
        else:
            try:
                if not all((env.email_address, env.organization)):
                    self.logger.warning("Use 'EMAIL_ADDRESS' and 'ORGANIZATION' to create a specific certificate.")
                generate_cert(common_name)
            except AssertionError as error:
                self.logger.error(error)
                self.logger.warning('Failed to generate self-signed SSL certificate and private key.')
                config_data["nginx.conf"] = self.get_config("nginx-non-ssl.conf", custom_servers)
            else:
                self.logger.info('Generated self-signed SSL certificate and private key.')
                self.server_copy(source=os.path.join(settings.current_dir, env.cert_file), destination=env.cert_file)
                self.server_copy(source=os.path.join(settings.current_dir, env.key_file), destination=env.key_file)
                config_data["options-ssl-nginx.conf"] = self.get_config("options-ssl-nginx.conf", custom_servers)
                config_data["nginx.conf"] = self.get_config("nginx-ssl.conf", custom_servers)
        return config_data

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
        if env.domain and env.subdomain:
            if env.subdomain.endswith(env.domain):
                endpoint = env.subdomain
                custom_servers += f' {env.subdomain}'
            else:
                endpoint = f'{env.subdomain}.{env.domain}'
                custom_servers += f' {env.subdomain}.{env.domain}'

        for i in range(10):
            try:
                self.nginx_server = Server(hostname=public_dns, pem_file=settings.key_pair_file, logger=self.logger)
                self.logger.info("Connection established in %s attempt", inflect.engine().ordinal(i + 1))
                break
            except Exception as error:
                self.logger.error(error)
                time.sleep(3)
        else:
            self.stop()
            raise TimeoutError(
                "Unable to connect SSH server"
            )

        load_and_copy = self.config_requirements(common_name=endpoint or public_dns, custom_servers=custom_servers)

        self.logger.info('Copying configuration files to %s', public_dns)
        self.nginx_server.server_write(data=load_and_copy)

        self.logger.info('Configuring nginx server.')
        nginx_status = self.nginx_server.run_interactive_ssh(
            commands=(
                "sudo apt-get update -y",
                "echo Y | sudo -S apt-get install nginx -y",
                f"sudo mv {settings.ssh_home}/nginx.conf /etc/nginx/nginx.conf",
                f"sudo mv {settings.ssh_home}/server.conf /etc/nginx/conf.d/server.conf",
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
            change_record_set(dns_name=env.domain, source=env.subdomain, destination=public_ip, record_type='A',
                              logger=self.logger, client=self.route53_client)
            self.logger.info('%s://%s -> http://localhost:%d', protocol, endpoint, env.port)
        else:
            self.logger.info('%s://%s -> http://localhost:%d', protocol, public_dns, env.port)

        self.logger.info('Initiating tunnel')
        self.nginx_server.initiate_tunnel()

    def stop(self, instance_id: str = None, security_group_id: str = None, public_ip: str = None) -> None:
        """Disables tunnelling by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        Args:
            instance_id: Instance that has to be terminated.
            security_group_id: Security group that has to be removed.
            public_ip: Public IP address to delete the A record from route53.
        """
        try:
            with open(env.server_info) as file:
                data = json.load(file)
        except FileNotFoundError:
            assert instance_id and security_group_id, \
                f'\n\nInput file: {env.server_info} is missing. Arguments are required to proceed.'
            data = {}

        security_group_id = security_group_id or data.get('security_group_id')
        instance_id = instance_id or data.get('instance_id')
        public_ip = public_ip or data.get('public_ip')

        self.delete_key_pair()
        sg_association = self.disassociate_security_group(instance_id=instance_id, security_group_id=security_group_id)
        instance = self.terminate_ec2_instance(instance_id=instance_id)
        if env.domain and env.subdomain and public_ip:
            change_record_set(dns_name=env.domain, source=env.subdomain, destination=public_ip,
                              record_type='A', action='DELETE', logger=self.logger, client=self.route53_client)
        if not sg_association and instance:
            try:
                instance.wait_until_terminated()  # todo: setup filters for wait until terminated
            except WaiterError as error:
                self.logger.error(error)
        self.delete_security_group(security_group_id)
        os.remove(env.server_info) if os.path.isfile(env.server_info) else None
