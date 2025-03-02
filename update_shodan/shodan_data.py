from enum import Enum

from netaddr import IPNetwork
from pydantic import BaseModel, Field, field_validator


class ShodanUsageLimits(BaseModel):
    scan_credits: int
    query_credits: int
    monitored_ips: int

    def __str__(self) -> str:
        message: str = f"Scan Credits: {self.scan_credits}\n"
        message += f"Query Credits: {self.query_credits}\n"
        message += f"Monitored IPs: {self.monitored_ips}\n"

        return message


class ShodanAPIInfo(BaseModel):
    scan_credits: int
    usage_limits: ShodanUsageLimits
    plan: str
    https: bool
    unlocked: bool
    query_credits: int
    monitored_ips: int
    unlocked_left: int
    telnet: bool

    def __str__(self) -> str:
        message: str = f"Scan Credits Remaining: {self.scan_credits}\n"
        message += f"Plan: {self.plan}\n"
        message += f"Usage Limits:\n"
        message += f"  {self.usage_limits}\n"
        message += f"HTTPS: {self.https}\n"
        message += f"Unlocked: {self.unlocked}\n"
        message += f"Unlocked left: {self.unlocked_left}\n"
        message += f"Query Credits: {self.query_credits}\n"
        message += f"Monitored IPs: {self.monitored_ips}\n"

        return message


class ShodanFilter(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    ip_network_list: list[IPNetwork] = Field(alias="ip")

    @field_validator("ip_network_list", mode="before")
    @classmethod
    def validate_ip(cls, value):
        if isinstance(value, str):
            return [IPNetwork(value)]

        if isinstance(value, list):
            return [IPNetwork(ip) for ip in value]

        raise TypeError("ip must be a string or list of strings")


class ShodanAlert(BaseModel):
    id: str
    name: str
    size: int
    filters: ShodanFilter

    def __str__(self) -> str:
        message: str = f"Name: {self.name}\n"
        message += f"ID: {self.id}\n"
        message += f"Size: {self.size}\n"
        message += f"Filters:\n"
        for address in self.filters.ip_network_list:
            message += f"  IP: {address.ip}\n"

        return message


class ShodanScanStatus(str, Enum):
    SUBMITTING = "SUBMITTING"
    QUEUE = "QUEUE"
    PROCESSING = "PROCESSING"
    DONE = "DONE"


class ShodanScanResult(BaseModel):
    count: int
    id: str
    status: ShodanScanStatus
    created: str

    def __str__(self) -> str:
        message: str = f"ID: {self.id}\n"
        message += f"IP Count: {self.count}\n"
        message += f"Status: {self.status.value}\n"
        message += f"Created: {self.created}\n"

        return message
