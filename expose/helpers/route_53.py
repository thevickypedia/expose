import logging
from typing import Dict, Union

import boto3
from botocore.exceptions import ClientError

from expose.helpers.defaults import AWSDefaults


def _get_zone_id(client: boto3.client, logger: logging.Logger, dns: str = None) -> str or None:
    """Gets the zone ID of a DNS name registered in route53.

    Args:
        client: Pre instantiated boto3 client.
        logger: Custom logger.
        dns: Takes the hosted zone name.

    Returns:
        str or None:
        Returns the zone ID.
    """
    response = client.list_hosted_zones_by_name(DNSName=dns, MaxItems='1')

    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
        logger.error(response)
        return

    if hosted_zones := response.get('HostedZones'):
        if zone_id := hosted_zones[0].get('Id'):
            return zone_id.split('/')[-1]
    else:
        logger.error(f'No HostedZones found for the DNSName: {dns}\n{response}')


def change_record_set(client: boto3.client, dns_name: str, source: str, destination: str,
                      record_type: str, logger: logging.Logger, action: str = 'UPSERT') -> Union[Dict, None]:
    """Adds a record set under an existing hosted zone.

    Args:
        client: Pre instantiated boto3 client.
        dns_name: Zone name.
        source: Source DNS name. Can be either ``subdomain.domain.com`` or just the ``subdomain``.
        destination: Destination hostnames or IP addresses.
        record_type: Type of the record to be added.
        logger: Custom logger.
        action: The action to perform.

    Returns:
        dict or None:
        ChangeSet response from AWS.
    """
    if record_type not in AWSDefaults.SUPPORTED_RECORDS:
        logger.error('Unsupported record type passed.')
        logger.warning(f"Should be one of {', '.join(sorted(AWSDefaults.SUPPORTED_RECORDS))}")
        return

    action = action.upper()
    if action not in AWSDefaults.SUPPORTED_ACTIONS:
        logger.error('Unsupported action type passed.')
        logger.warning(f"Should be one of {', '.join(sorted(AWSDefaults.SUPPORTED_ACTIONS))}")
        return

    if not source.endswith(dns_name):
        source = f'{source}.{dns_name}'
    logger.info("%s `%s` record::%s -> %s", action, record_type, source, destination)
    try:
        response = client.change_resource_record_sets(
            HostedZoneId=_get_zone_id(logger=logger, dns=dns_name, client=client),
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
    logger.info(response.get('ChangeInfo'))
