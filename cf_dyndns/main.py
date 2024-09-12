import argparse
import logging
import signal
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Any

import httpx

from .api import (
    CloudflareClient,
    CloudflareRecordNotFoundError,
    CloudflareZoneNotFoundError,
    CreateDNSRecord,
    DNSRecord,
    Zone,
)

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    prog='cf_dyndns', description='Dynamically update Cloudflare DNS records'
)

parser.add_argument('-c', '--config', required=True, help='Path to config file')
parser.add_argument(
    '-t',
    '--timeout',
    default=60,
    type=int,
    help='How long to wait before re-running. Set to 0 to only run once.',
)
parser.add_argument(
    '-d',
    '--dry-run',
    default=False,
    action='store_true',
    help='Do everything except for updating the records',
)

parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose logging')
parser.add_argument('-n', '--create', help='Creating missing DNS Records', action='store_true')

run = Event()


def handler(signum: int, _: FrameType | None):
    if signum == signal.SIGINT:
        logger.info('Got SIGINT. Shutting down...')
        run.set()


signal.signal(signal.SIGINT, handler)


class IPVer(StrEnum):
    v4 = 'ipv4'
    v6 = 'ipv6'


@dataclass
class WebsiteConfig:
    name: str
    zone: str
    ipv4: bool
    ipv6: bool

    @staticmethod
    def from_config(config: dict[str, Any]) -> list['WebsiteConfig']:
        return [WebsiteConfig(k, **config[k]) for k in config]


def get_ip(ip_ver: IPVer) -> IPv6Address | IPv4Address | None:
    url = f'https://{ip_ver}.icanhazip.com'
    logger.debug('requesting %s from %s', ip_ver, url)
    try:
        response = httpx.get(url, timeout=5)
    except httpx.HTTPError:
        logger.warning('Failed to get %s. Skipping', ip_ver)
        return None
    logger.debug('%s responded with %s', url, response.text)
    return ip_address(response.text.strip())


def get_ipv4() -> IPv4Address:
    ip = get_ip(IPVer.v4)
    logger.debug('Got ipv4: %s', ip)
    if not isinstance(ip, IPv4Address):
        txt = f'Expected IPv4Address but got {type(ip)}'
        raise TypeError(txt)

    return ip


def get_ipv6() -> IPv6Address | None:
    ip = get_ip(IPVer.v6)
    logger.debug('Got ipv6: %s', ip)
    if not isinstance(ip, IPv6Address):
        txt = f'Expected IPv6Address but got {type(ip)}'
        logger.warning(txt)
        return None

    return ip


def update_website(
    cf: CloudflareClient,
    website: WebsiteConfig,
    ipv4: IPv4Address,
    ipv6: IPv6Address | None,
    dry_run: bool,  # noqa: FBT001
    create_missing_records: bool = False,
):
    logger.info('updating %s (ipv4: %s, ipv6: %s)', website.name, website.ipv4, website.ipv6)
    try:
        zone_id = Zone.get_by_name(website.zone, cf).zone_id
    except CloudflareZoneNotFoundError:
        logger.warning('%s zone not found', website.zone)
        return

    for ip_ver in [IPVer.v4, IPVer.v6]:
        if ip_ver == IPVer.v4 and not website.ipv4:
            logger.info('Skipping ipv4')
            continue

        if ip_ver == IPVer.v6 and ipv6 is None:
            logger.warning('No IPv6 address available. Skipping')
            continue

        if ip_ver == IPVer.v6 and not website.ipv6:
            logger.info('Skipping ipv6')
            continue

        ip = ipv4 if ip_ver == IPVer.v4 else ipv6
        record_type = 'A' if ip_ver == IPVer.v4 else 'AAAA'

        try:
            record = DNSRecord.get_record_by_name_and_type(zone_id, website.name, record_type, cf)
        except CloudflareRecordNotFoundError:
            logger.debug('%s record not found for %s. Creating...', record_type, website.name)
            if create_missing_records:
                logger.info('%s ')
                new_records = CreateDNSRecord(
                    content=str(ip),
                    name=website.name,
                    proxied=False,
                    type=record_type,
                    comment='Created by dnsupdate (https://github.com/onestay/cf-dyndns)',
                )

                if dry_run:
                    logger.info('dry run set. Not creating')
                    continue
                DNSRecord.create(new_records, zone_id, cf)
            else:
                logger.warning('%s record not found for %s', record_type, website.name)
            continue

        logger.debug('%s record found for %s: %s', record_type, website.name, record.content)

        if record.content == str(ip):
            logger.debug(
                '%s record for %s is up to date (%s)',
                record_type,
                website.name,
                record.content,
            )
            continue

        logger.info(
            '%s record for %s is out of date\n\tfound: %s\n\texpected:%s',
            record_type,
            website.name,
            record.content,
            ip,
        )
        updated_record = CreateDNSRecord(content=str(ip), name=website.name, type=record_type)

        if dry_run:
            logger.info('dry run set. Not updating')
            continue

        DNSRecord.update_record(zone_id, record.record_id, updated_record, cf)


def main():
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    config_file = Path(args.config)

    with config_file.open('rb') as cf:
        config = tomllib.load(cf)

    general = config.pop('general')
    logger.debug('Creating Cloudflare connection')
    cf = CloudflareClient(general['cloudflare_api_key'])

    websites = WebsiteConfig.from_config(config)
    while not run.is_set():
        logger.debug('Getting IP addresses')
        ipv4 = get_ipv4()
        ipv6 = get_ipv6()

        for website in websites:
            update_website(cf, website, ipv4, ipv6, args.dry_run, args.create)

        if args.timeout == 0:
            break

        logger.debug('Sleeping for %s seconds', args.timeout)

        run.wait(args.timeout)


if __name__ == '__main__':
    main()
