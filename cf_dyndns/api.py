from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

import requests
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.cloudflare.com/client/v4"


class CloudflareRequestError(Exception):
    def __init__(self, res: requests.Response) -> None:
        msg = "cf error"
        errors = res.json()["errors"]
        errors = [f"{error['message']} ({error['code']})" for error in errors]
        error_msg = "\t\n".join(errors)
        msg = f"{res.url} failed with {res.status_code}: {error_msg}"
        super().__init__(msg)


class CloudflareZoneNotFoundError(Exception):
    pass

class CloudflareRecordNotFoundError(Exception):
    pass


def _make_url(endpoint: str, base: str = _BASE_URL) -> str:
    base = base.rstrip("/")
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    return base + endpoint


class CloudflareClient:
    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self.api_key = api_key
        self.client = requests.session()
        self.client.headers.update({"Authorization": f"Bearer {self.api_key}"})
        self.timeout = timeout

    def do_put(
        self,
        endpoint: str,
        params: dict[str, str] | None = None,
        body: str | None = None,
    ):
        url = _make_url(endpoint)
        if params is not None:
            url = url + f"?{urlencode(params)}"

        response = self.client.put(url, data=body, timeout=self.timeout)

        json_response = response.json()
        if not json_response["success"]:
            raise CloudflareRequestError(response)

        return json_response["result"]

    def do_post(
        self,
        endpoint: str,
        params: dict[str, str] | None = None,
        body: str | None = None,
    ):
        url = _make_url(endpoint)
        if params is not None:
            url = url + f"?{urlencode(params)}"

        response = self.client.post(url, data=body, timeout=self.timeout)

        json_response = response.json()
        if not json_response["success"]:
            raise CloudflareRequestError(response)

        return json_response["result"]

    def do_get(
        self, endpoint: str, params: dict[str, str] | None = None
    ) -> list[dict[Any, Any]]:
        url = _make_url(endpoint)
        if params is not None:
            url = url + f"?{urlencode(params)}"

        response = self.client.get(url, timeout=self.timeout)

        json_response = response.json()
        if not json_response["success"]:
            raise CloudflareRequestError(response)

        return json_response["result"]


class Zone(BaseModel):
    created_on: datetime
    zone_id: str = Field(alias="id")
    name: str

    @staticmethod
    def list_zones(cf: CloudflareClient) -> list[Zone]:
        return [Zone(**result) for result in cf.do_get("zones")]

    @staticmethod
    def get_by_name(hostname: str, cf: CloudflareClient) -> Zone:
        response = cf.do_get("zones", {"name": hostname})
        try:
            zone = response[0]
        except IndexError as e:
            msg = f"zone with name '{hostname}' not found"
            raise CloudflareZoneNotFoundError(msg) from e

        return Zone(**zone)


class CreateDNSRecord(BaseModel):
    content: str
    name: str
    proxied: bool | None = None
    record_type: str = Field(alias="type")
    comment: str | None = None
    tags: list[str] | None = None
    ttl: int | None = None


class DNSRecord(BaseModel):
    content: str
    record_type: str = Field(alias="type")
    record_id: str = Field(alias="id")
    comment: str | None
    zone_id: str
    zone_name: str
    ttl: int
    created_on: datetime
    locked: bool

    @staticmethod
    def create(create_dns_record: CreateDNSRecord, zone_id: str, cf: CloudflareClient):
        request_body = create_dns_record.model_dump_json(
            by_alias=True, exclude_unset=True
        )

        return DNSRecord(
            **cf.do_post(f"/zones/{zone_id}/dns_records", body=request_body)
        )

    @staticmethod
    def list_all_records(zone_id: str, cf: CloudflareClient):
        return [
            DNSRecord(**result)
            for result in cf.do_get(f"/zones/{zone_id}/dns_records")
        ]

    @staticmethod
    def get_record_by_name_and_type(zone_id: str, name: str, record_type: str, cf: CloudflareClient) -> DNSRecord:
        response = cf.do_get(f"zones/{zone_id}/dns_records", {"name": name, "type": record_type})
        try:
            record = response[0]
        except IndexError as e:
            msg = f"record with name '{name}' and type '{record_type}' not found"
            raise CloudflareRecordNotFoundError(msg) from e

        return DNSRecord(**record)

    @staticmethod
    def update_record(zone_id: str, record_id: str, create_dns_record: CreateDNSRecord, cf: CloudflareClient) -> DNSRecord:
        request_body = create_dns_record.model_dump_json(by_alias=True, exclude_unset=True)

        return DNSRecord(
            **cf.do_put(f"/zones/{zone_id}/dns_records/{record_id}", body=request_body)
        )
