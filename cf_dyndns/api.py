from __future__ import annotations

import logging
from datetime import datetime  # noqa: TCH003
from typing import Any
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

_BASE_URL = 'https://api.cloudflare.com/client/v4'


class CloudflareRequestError(Exception):
    def __init__(self, res: httpx.Response) -> None:
        msg = 'cf error'
        errors = res.json()['errors']
        errors = [f"{error['message']} ({error['code']})" for error in errors]
        error_msg = '\t\n'.join(errors)
        msg = f'{res.url} failed with {res.status_code}: {error_msg}'
        super().__init__(msg)


class CloudflareResponseParseError(Exception):
    pass


class CloudflareZoneNotFoundError(Exception):
    pass


class CloudflareRecordNotFoundError(Exception):
    pass


def _make_url(endpoint: str, base: str = _BASE_URL) -> str:
    base = base.rstrip('/')
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint

    return base + endpoint


class CloudflareClient:
    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self.api_key = api_key
        self.client = httpx.Client(timeout=timeout, http2=True)
        self.client.headers.update({'Authorization': f'Bearer {self.api_key}'})

    def do_put(
        self,
        endpoint: str,
        params: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ):
        url = _make_url(endpoint)
        if params is not None:
            url = url + f'?{urlencode(params)}'

        response = self.client.put(url, json=body)

        json_response = response.json()
        if not json_response['success']:
            raise CloudflareRequestError(response)

        return json_response['result']

    def do_post(
        self,
        endpoint: str,
        params: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ):
        url = _make_url(endpoint)
        if params is not None:
            url = url + f'?{urlencode(params)}'

        response = self.client.post(url, json=body)

        json_response = response.json()
        if not json_response['success']:
            print(body)
            raise CloudflareRequestError(response)

        return json_response['result']

    def do_get(self, endpoint: str, params: dict[str, str] | None = None) -> list[dict[Any, Any]]:
        url = _make_url(endpoint)

        response = self.client.get(url, params=params)

        json_response = response.json()
        if not json_response['success']:
            raise CloudflareRequestError(response)

        return json_response['result']


_zone_cache: dict[str, Zone] = {}


class Zone(BaseModel):
    created_on: datetime
    zone_id: str = Field(alias='id')
    name: str

    @staticmethod
    def list_zones(cf: CloudflareClient) -> list[Zone]:
        return [Zone(**result) for result in cf.do_get('zones')]

    @staticmethod
    def get_by_name(hostname: str, cf: CloudflareClient) -> Zone:
        if hostname in _zone_cache:
            return _zone_cache[hostname]
        response = cf.do_get('zones', {'name': hostname})
        try:
            zone = response[0]
        except IndexError as e:
            msg = f"zone with name '{hostname}' not found"
            raise CloudflareZoneNotFoundError(msg) from e

        try:
            parsed_zone = Zone.model_validate(zone)
        except ValidationError as err:
            msg = f'Could not construct a zone from response:\n{zone}'
            raise CloudflareResponseParseError(msg) from err

        return parsed_zone


class CreateDNSRecord(BaseModel):
    content: str
    name: str
    proxied: bool | None = None
    record_type: str = Field(alias='type')
    comment: str | None = None
    tags: list[str] | None = None
    ttl: int | None = None


class DNSRecord(BaseModel):
    content: str
    record_type: str = Field(alias='type')
    record_id: str = Field(alias='id')
    comment: str | None
    zone_id: str
    zone_name: str
    ttl: int
    created_on: datetime

    @classmethod
    def parse_record(cls, resp: Any) -> DNSRecord:
        try:
            parsed_record = cls.model_validate(resp)
        except ValidationError as err:
            msg = f'Could not construct DNSRecord from response:\n{resp}'
            raise CloudflareResponseParseError(msg) from err
        return parsed_record

    @classmethod
    def create(cls, create_dns_record: CreateDNSRecord, zone_id: str, cf: CloudflareClient):
        request_body = create_dns_record.model_dump(by_alias=True, exclude_unset=True)

        resp = cf.do_post(f'/zones/{zone_id}/dns_records', body=request_body)
        return cls.parse_record(resp)

    @classmethod
    def list_all_records(cls, zone_id: str, cf: CloudflareClient) -> list[DNSRecord]:
        responses = cf.do_get(f'/zones/{zone_id}/dns_records')

        return [cls.parse_record(resp) for resp in responses]

    @classmethod
    def get_record_by_name_and_type(
        cls, zone_id: str, name: str, record_type: str, cf: CloudflareClient
    ) -> DNSRecord:
        response = cf.do_get(f'zones/{zone_id}/dns_records', {'name': name, 'type': record_type})
        try:
            record = response[0]
        except IndexError as e:
            msg = f"record with name '{name}' and type '{record_type}' not found"
            raise CloudflareRecordNotFoundError(msg) from e

        return cls.parse_record(record)

    @classmethod
    def update_record(
        cls, zone_id: str, record_id: str, create_dns_record: CreateDNSRecord, cf: CloudflareClient
    ) -> DNSRecord:
        request_body = create_dns_record.model_dump(by_alias=True, exclude_unset=True)

        resp = cf.do_put(f'/zones/{zone_id}/dns_records/{record_id}', body=request_body)

        return cls.parse_record(resp)
