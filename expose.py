import json
import logging
from json import dump, load
from os import environ, path, system, getcwd
from sys import stdout
from time import perf_counter, sleep
from urllib.request import urlopen

from boto3 import client, resource
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from route_53 import change_record_set

disable_warnings(InsecureRequestWarning)  # Disable warnings for self-signed certificates

if path.isfile('.env'):
    load_dotenv(dotenv_path='.env', verbose=True, override=True)


def time_converter(seconds: float) -> str:
    """Modifies seconds to appropriate days/hours/minutes/seconds.

    Args:
        seconds: Takes number of seconds as argument.

    Returns:
        str:
        Seconds converted to days or hours or minutes or seconds.
    """
    days = round(seconds // 86400)
    seconds = round(seconds % (24 * 3600))
    hours = round(seconds // 3600)
    seconds %= 3600
    minutes = round(seconds // 60)
    seconds %= 60
    if days:
        return f'{days} days, {hours} hours, {minutes} minutes, and {seconds} seconds'
    elif hours:
        return f'{hours} hours, {minutes} minutes, and {seconds} seconds'
    elif minutes:
        return f'{minutes} minutes, and {seconds} seconds'
    elif seconds:
        return f'{seconds} seconds'


def _sleeper(sleep_time: int) -> None:
    """Sleeps for a particular duration and prints the remaining time in console output.

    Args:
        sleep_time: Takes the time script has to sleep, as an argument.
    """
    sleep(1)
    for i in range(sleep_time):
        stdout.write(f'\rRemaining: {sleep_time - i:0{len(str(sleep_time))}}s')
        sleep(1)
    stdout.write('\r')


def get_public_ip() -> str:
    """Gets the public IP address from ``ipinfo.io`` or ``ip.jsontest.com``.

    Returns:
        str:
        Returns the public IP address.
    """
    public_ip = json.load(urlopen('https://ipinfo.io/json')).get('ip') or \
        json.loads(urlopen('http://ip.jsontest.com').read()).get('ip')
    return public_ip


class VirtualMachine:
    """Initiates ``VirtualMachine`` object to spin up an EC2 instance with a pre-configured AMI which acts as a tunnel.

    >>> VirtualMachine

    """

    def __init__(self, aws_access_key: str = environ.get('ACCESS_KEY'), aws_secret_key: str = environ.get('SECRET_KEY'),
                 aws_region_name: str = environ.get('REGION_NAME', 'us-west-2')):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            aws_access_key: Access token for AWS account.
            aws_secret_key: Secret ID for AWS account.
            aws_region_name: Region where the instance should live. Defaults to ``us-west-2``

        See Also:
            - If no values (for aws authentication) are passed during object initialization, script checks for env vars.
            - If the environment variables are ``null``, gets the default credentials from ``~/.aws/credentials``.
        """
        # Hard-coded certificate file name, server information file name, security group name
        self.key_name = 'VirtualMachine'
        self.server_file = 'server_info.json'
        self.security_group_name = 'VirtualMachine Access Server'

        # Logger setup
        self.logger = logging.getLogger(__name__)
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
            datefmt='%b-%d-%Y %I:%M:%S %p'
        )
        handler = logging.StreamHandler()
        handler.setFormatter(fmt=formatter)
        handler.setLevel(level=logging.DEBUG)
        self.logger.addHandler(hdlr=handler)
        self.logger.setLevel(level=logging.DEBUG)

        # AWS client and resource setup
        self.region = aws_region_name
        self.ec2_client = client(service_name='ec2', region_name=aws_region_name,
                                 aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
        self.ec2_resource = resource(service_name='ec2', region_name=aws_region_name,
                                     aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)

    def __del__(self):
        """Destructor to print the run time at the end."""
        self.logger.info(f'Total runtime: {time_converter(perf_counter())}')

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
            Flag to indicate the calling function if or not the security group was authorized.
        """
        try:
            response = self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     # 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # Makes instance accessible from anywhere but insecure
                     'IpRanges': [{'CidrIp': f'{public_ip}/32'}, {'CidrIp': f'{get_public_ip()}/32'}]},
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

    def _create_ec2_instance(self, image_id: str = environ.get('AMI_ID')) -> str or None:
        """Creates an EC2 instance of type ``t2.micro`` with the pre-configured AMI id.

        Args:
            image_id: Takes image ID as an argument. Defaults to ``ami_id`` in environment variable. Exits if `null`.

        Returns:
            str or None:
            Instance ID.
        """
        if not image_id:
            self.logger.error('AMI is mandatory to spin up an EC2 instance. Received `null`')
            return

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
                ImageId=image_id,
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
                system(f'rm {self.key_name}.pem')
            return True
        else:
            self.logger.error(f'Failed to delete the key: {self.key_name}')

    def _delete_security_group(self, security_group_id: str) -> bool:
        """Deletes the security group.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        Returns:
            bool:
            Flag to indicate the calling function if or not the SecurityGroup was deleted.
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
            Flag to indicate the calling function if or not the instance was terminated.
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
        _sleeper(sleep_time=30)
        while True:
            sleep(3)
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

    def startup_tunnel(self, port: int = environ.get('PORT')) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the VirtualMachine.

        Args:
            port: Port number where the application/API is running in localhost.
        """
        if path.isfile(self.server_file) and path.isfile(f'{self.key_name}.pem'):
            self.logger.warning(f'Received request to start VM, '
                                f'but {self.server_file} and {self.key_name}.pem')
            return

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
            'start_tunneling': f"ssh -i {self.key_name}.pem -R 8080:localhost:{port} ubuntu@{public_dns}"
        }

        self.logger.info(f'Restricting wide open permissions to {self.key_name}.pem')
        system(f'chmod 400 {self.key_name}.pem')

        with open(self.server_file, 'w') as file:
            dump(instance_info, file, indent=2)

        self.logger.info('Waiting for SSH origin to be active.')
        _sleeper(sleep_time=20)

        self._configure_vm(public_dns=public_dns, public_ip=public_ip, port=port)

    def _configure_vm(self, public_dns: str, public_ip: str, port: int,
                      domain_name: str = environ.get('DOMAIN'), subdomain: str = environ.get('SUBDOMAIN')):
        """Configures the VirtualMachine to redirect traffic from localhost.

        Args:
            public_dns: Public DNS name of the EC2 that was created.
            public_ip: Public IP of the EC2 that was created.
            port: Port number on which the app/api is running.
            domain_name: Name of the hosted zone in which an ``A`` record has to be added. [``example.com``]
            subdomain: Subdomain using which the localhost has to be accessed. [``tunnel`` or ``tunnel.example.com``]
        """
        self.logger.info('Gathering pieces for configuration.')
        custom_servers = f"{public_dns} {public_ip}"
        endpoint = None
        if domain_name and subdomain:
            if subdomain.endswith(domain_name):
                endpoint = subdomain
                custom_servers += f' {subdomain}'
            else:
                endpoint = f'{subdomain}.{domain_name}'
                custom_servers += f' {subdomain}.{domain_name}'

        with open('server.conf') as file:
            configuration = file.read()
        configuration = configuration.replace('PERSONALIZATION', custom_servers)
        with open('server.conf', 'w') as file:
            file.write(configuration)

        nginx_config = f"""osascript -e '
tell application "Terminal"
    delay 5
    set currentTab to do script ("cd {getcwd()}")
    set current settings of currentTab to settings set "Ocean"
    delay 2
    do script ("scp -i {self.key_name}.pem server.conf ubuntu@{public_dns}:/home/ubuntu/") in currentTab
    delay 2
    do script ("yes") in currentTab
    delay 5
    do script ("scp -i {self.key_name}.pem nginx.conf ubuntu@{public_dns}:/home/ubuntu/") in currentTab
    delay 5
    do script ("ssh -i VirtualMachine.pem ubuntu@{public_dns}") in currentTab
    delay 10
    do script ("sudo apt update")  in currentTab
    delay 20
    do script ("echo Y | sudo -S apt install nginx") in currentTab
    delay 25
    do script ("sudo mv /home/ubuntu/server.conf /etc/nginx/conf.d/server.conf") in currentTab
    delay 5
    do script ("sudo mv /home/ubuntu/nginx.conf /etc/nginx/nginx.conf") in currentTab
    delay 5
    do script ("sudo service nginx start") in currentTab
    delay 5
    do script ("logout") in currentTab
    delay 2
    do script ("exit") in currentTab
end tell
' > /dev/null 2>&1
"""

        start_tunnel = f"""osascript -e '
tell application "Terminal"
    delay 5
    set currentTab to do script ("cd {getcwd()}")
    set current settings of currentTab to settings set "Ocean"
    delay 2
    do script ("ssh -i {self.key_name}.pem -R 8080:localhost:{port} ubuntu@{public_dns}") in currentTab
end tell
' > /dev/null 2>&1
"""

        restart_server = f"""osascript -e '
tell application "Terminal"
    delay 5
    set currentTab to do script ("cd {getcwd()}")
    set current settings of currentTab to settings set "Ocean"
    delay 2
    do script ("ssh -i VirtualMachine.pem ubuntu@{public_dns}") in currentTab
    delay 10
    do script ("sudo service nginx stop") in currentTab
    delay 3
    do script ("sudo service nginx start") in currentTab
    delay 3
    do script ("logout") in currentTab
    delay 2
    do script ("exit") in currentTab
end tell
' > /dev/null 2>&1
"""

        self.logger.info(f'Configuring nginx server.')
        config_status = system(nginx_config)
        if config_status == 256:
            self.logger.info(f'Failed to configure nginx server. Run the commands in {self.server_file} manually.')
            return

        self.logger.info('Nginx server was configured successfully.')
        system('git checkout -- server.conf')

        self.logger.info('Initiating tunnel')
        tunnel_status = system(start_tunnel)
        if tunnel_status == 256:
            self.logger.info('Failed to start up tunnel. `ssh` manually and restart the nginx server.')
            return

        self.logger.info('Initiating restart')
        restart_status = system(restart_server)
        if restart_status == 256:
            self.logger.info('Restart failed. Restart the server manually.')
            return

        if endpoint:
            self.logger.info(f'Localhost can be accessed via http://{endpoint} [OR] http://{public_dns}')
            change_record_set(dns_name=domain_name, source=subdomain, destination=public_ip, record_type='A')

    def shutdown_tunnel(self) -> None:
        """Disables tunnelling by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        See Also:
            There is a minute delay to delete the SecurityGroup as it awaits instance termination. This may run twice.
        """
        if not path.exists(self.server_file):
            self.logger.info(f'Input file: {self.server_file} is missing. CANNOT proceed.')
            return

        with open(self.server_file, 'r') as file:
            data = load(file)

        if self._delete_key_pair() and self._terminate_ec2_instance(instance_id=data.get('instance_id')):
            self.logger.info('Waiting for dependent objects to delete SecurityGroup.')
            while True:
                if self._delete_security_group(security_group_id=data.get('security_group_id')):
                    break
                else:
                    _sleeper(sleep_time=60)
            system(f'rm {self.server_file}')
            if (domain_name := environ.get('DOMAIN')) and (subdomain := environ.get('SUBDOMAIN')):
                change_record_set(dns_name=domain_name, source=subdomain, destination=data.get('public_ip'),
                                  record_type='A', action='DELETE')


if __name__ == '__main__':
    VirtualMachine().startup_tunnel()
