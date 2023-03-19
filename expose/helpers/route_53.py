import logging

import boto3
from botocore.exceptions import ClientError

client = boto3.client('route53')


def _get_zone_id(logger: logging.Logger, dns: str = None) -> str or None:
    """Gets the zone ID of a DNS name registered in route53.

    Args:
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


def change_record_set(dns_name: str, source: str, destination: str, record_type: str, logger: logging.Logger,
                      action: str = 'UPSERT') -> dict or None:
    """Adds a record set under an existing hosted zone.

    Args:
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
    supported_records = ['SOA', 'A', 'TXT', 'NS', 'CNAME', 'MX', 'NAPTR', 'PTR', 'SRV', 'SPF', 'AAAA', 'CAA', 'DS']
    if record_type not in supported_records:
        logger.error('Unsupported record type passed.')
        logger.warning(f"Should be one of {', '.join(sorted(supported_records))}")
        return

    action = action.upper()
    supported_actions = ['CREATE', 'DELETE', 'UPSERT']
    if action not in supported_actions:
        logger.error('Unsupported action type passed.')
        logger.warning(f"Should be one of {', '.join(sorted(supported_actions))}")
        return

    if not source.endswith(dns_name):
        source = f'{source}.{dns_name}'
    logger.info("%s `%s` record::%s -> %s", action, record_type, source, destination)
    try:
        response = client.change_resource_record_sets(
            HostedZoneId=_get_zone_id(logger=logger, dns=dns_name),
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
