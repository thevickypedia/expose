import logging
from http.client import responses as http_response
from typing import Dict, Union

import boto3
from botocore.exceptions import ClientError

from expose.helpers.defaults import AWSDefaults
from expose.helpers.warnings import AWSResourceError


def get_zone_id(client: boto3.client,
                logger: logging.Logger,
                dns: str,
                init: bool = False) -> str or None:
    """Gets the zone ID of a DNS name registered in route53.

    Args:
        client: Pre instantiated boto3 client.
        logger: Custom logger.
        dns: Takes the hosted zone name.
        init: Initializer.

    Returns:
        str or None:
        Returns the zone ID.
    """
    response = client.list_hosted_zones_by_name(DNSName=dns, MaxItems='10')

    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
        logger.error(response)
        if init:
            status_code = response.get('ResponseMetadata', {}).get('HTTPStatusCode', 500)
            raise AWSResourceError(status_code, http_response[status_code])
        return

    if hosted_zones := response.get('HostedZones'):
        for hosted_zone in hosted_zones:
            if hosted_zone['Name'] in (dns, f'{dns}.'):
                return hosted_zone['Id'].split('/')[-1]
    if init:
        raise AWSResourceError(404, f'No HostedZones found for the DNSName: {dns}')
    logger.error(f'No HostedZones found for the DNSName: {dns}\n{response}')


def change_record_set(client: boto3.client,
                      source: str,
                      destination: str,
                      record_type: str,
                      logger: logging.Logger,
                      zone_id: str,
                      action: str = 'UPSERT') -> Union[Dict, None]:
    """Adds a record set under an existing hosted zone.

    Args:
        client: Pre instantiated boto3 client.
        source: Source DNS name. Can be either ``subdomain.domain.com`` or just the ``subdomain``.
        destination: Destination hostnames or IP addresses.
        record_type: Type of the record to be added.
        logger: Custom logger.
        zone_id: Hosted zone ID.
        action: The action to perform.

    Returns:
        dict or None:
        ChangeSet response from AWS.
    """
    record_type = record_type.upper()
    if record_type not in AWSDefaults.SUPPORTED_RECORDS:
        logger.error('Unsupported record type passed.')
        logger.warning(f"Should be one of {', '.join(sorted(AWSDefaults.SUPPORTED_RECORDS))}")
        return

    action = action.upper()
    if action not in AWSDefaults.SUPPORTED_ACTIONS:
        logger.error('Unsupported action type passed.')
        logger.warning(f"Should be one of {', '.join(sorted(AWSDefaults.SUPPORTED_ACTIONS))}")
        return

    logger.info("%s `%s` record::%s -> %s", action, record_type, source, destination)
    try:
        response = client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': f'{record_type}: {source} -> {destination}',
                'Changes': [
                    {
                        'Action': action,
                        'ResourceRecordSet': {
                            'Name': source,
                            'Type': record_type,
                            'TTL': 300,
                            'ResourceRecords': [{'Value': destination}],
                        }
                    },
                ]
            }
        )
    except ClientError as error:
        logger.error(error)
        return
    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
        logger.error(response)
        return
    logger.info(response.get('ChangeInfo', {}).get('Comment'))
    logger.debug(response.get('ChangeInfo'))
