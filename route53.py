"""Route53 record mangling code."""

import collections
import logging
import time

import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError

logger = logging.getLogger(__name__)

class Route53Client:
    ttl = 10

    def __init__(self, accesskey, secretkey):
        self._r53 = boto3.client("route53", aws_access_key_id=accesskey, aws_secret_access_key=secretkey)

    def _find_zone_id_for_domain(self, domain):
        """Find the zone id responsible a given FQDN.
           That is, the id for the zone whose name is the longest parent of the
           domain.
        """
        paginator = self._r53.get_paginator("list_hosted_zones")
        zones = []
        target_labels = domain.rstrip(".").split(".")
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if zone["Config"]["PrivateZone"]:
                    continue

                candidate_labels = zone["Name"].rstrip(".").split(".")
                if candidate_labels == target_labels[-len(candidate_labels):]:
                    zones.append((zone["Name"], zone["Id"]))

        if not zones:
            raise Exception(
                "Unable to find a Route53 hosted zone for {0}".format(domain)
            )

        # Order the zones that are suffixes for our desired to domain by
        # length, this puts them in an order like:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        # And then we choose the first one, which will be the most specific.
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _set_txt_record(self, domain, value):
        zone_id = self._find_zone_id_for_domain(domain)
        rrecords = [{"Value": '"{0}"'.format(value)}]
        response = self._r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "acmeproxy certificate validation.",
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "TXT",
                            "TTL": self.ttl,
                            "ResourceRecords": rrecords,
                        }
                    }
                ]
            }
        )
        return response["ChangeInfo"]["Id"]

    def _del_txt_record(self, domain):
        zone_id = self._find_zone_id_for_domain(domain)
        logger.debug('Got zoneid = %s' % zone_id)
        response = self._r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "certbot-dns-route53 certificate validation DELETE",
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "TXT",
                            "TTL": self.ttl,
                            "ResourceRecords": [ { "Value": '""'} ],
                        }
                    }
                ]
            }
        )
        return response["ChangeInfo"]["Id"] 

    def create_record(self, domain, value):
        logger.debug('Creating TXT in domain %s with %s..' % (domain, value))
    
        changeid = self._set_txt_record(domain, value)
        logger.debug('Got changeid = %s' % changeid)

        logger.info('Creation for %s submitted..' % domain)


    def delete_record(self, domain):
        logger.debug('Removing TXT in domain %s ..' % domain)
    
        changeid = self._set_txt_record(domain, '')
        changeid = self._del_txt_record(domain)
    
        logger.debug('Got changeid = %s' % changeid)
        logger.info('Deletion for %s submitted..' % domain)

    
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
