from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlencode, urljoin
from ipaddress import IPv4Address, IPv6Address

import requests
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.cloudflare.com/client/v4/"

class CloudflareRequestError(Exception):
    def __init__(self, res: requests.Response) -> None:
        msg = "cf error"
        try:
            errors = res.json()["errors"]
            errors = [f"{errors[i]['message']} ({errors[i]['code']})" for (i,_) in enumerate(errors)]
            error_msg = '\t\n'.join(errors)
            msg = f"{res.url} failed with {res.status_code}: {error_msg}"
        finally:
            super().__init__(msg)

class CloudflareClient:
    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self.api_key = api_key
        self.client = requests.session()
        self.client.headers.update({"Authorization": f"Bearer {self.api_key}"})
        self.timeout = timeout

    def do_get(self, endpoint: str, params: dict[str, str] | None = None) -> list[dict[Any, Any]]:
        url = urljoin(_BASE_URL, endpoint)
        if params is not None:
            url = url + f"?{urlencode(params)}"

        response = self.client.get(url, timeout=self.timeout)

        json_response = response.json()
        if not json_response['success']:
            raise CloudflareRequestError(response)

        return json_response['result']

class Zone(BaseModel):
    created_on: datetime
    zone_id: str = Field(alias="id")
    name: str
    _cf: CloudflareClient

    @staticmethod
    def list_zones(cf: CloudflareClient) -> list[Zone]:
        return [Zone(**result, _cf=cf) for result in cf.do_get("zones")]

class DNSRecord(BaseModel):
    content: IPv4Address | IPv6Address
    record_type: str = Field(alias="type")
    record_id: str = Field(alias="type")
    comment: str | None
    zone_id: str
    zone_name: str
    ttl: int
    created_on: datetime
    locked: bool
    _cf: CloudflareClient

    @staticmethod
    def list_all_records(zone_id: str, cf: CloudflareClient):
        return [DNSRecord(**result, _cf=cf) for result in cf.do_get(f"/zones/{zone_id}/dns_records")]
if __name__ == "__main__":
    cf = CloudflareClient("")
    zones = Zone.list_zones(cf)
    records = DNSRecord.list_all_records(zones[0].zone_id, cf)
    print(records)
