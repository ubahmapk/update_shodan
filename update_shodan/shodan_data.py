from enum import Enum

from netaddr import IPNetwork
from pydantic import BaseModel, Field, field_validator


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
        message: str = f"Count: {self.count}\n"
        message += f"ID: {self.id}\n"
        message += f"Status: {self.status.value}\n"
        message += f"Created: {self.created}\n"

        return message
