from enum import Enum

from netaddr import IPNetwork
from pydantic import BaseModel, Field, field_validator


class ShodanUsageLimits(BaseModel):
    """
    Represents the usage limits for Shodan API.

    Attributes
    ----------
    scan_credits : int
        The number of scan credits available.
    query_credits : int
        The number of query credits available.
    monitored_ips : int
        The number of monitored IPs.

    Raises
    ------
    None

    Returns
    -------
    str
        A string representation of the Shodan usage limits.
    """

    scan_credits: int
    query_credits: int
    monitored_ips: int

    def __str__(self) -> str:
        message: str = (
            f"Scan Credits: {self.scan_credits}"
            f"Query Credits: {self.query_credits}"
            f"Monitored IPs: {self.monitored_ips}"
        )

        return message


class ShodanAPIInfo(BaseModel):
    """
    Represents the information retrieved from the Shodan API.

    Attributes
    ----------
    scan_credits : int
        The number of scan credits remaining.
    usage_limits : ShodanUsageLimits
        The usage limits for the Shodan API.
    plan : str
        The plan associated with the Shodan API key.
    https : bool
        Indicates if HTTPS is enabled.
    unlocked : bool
        Indicates if the account is unlocked.
    query_credits : int
        The number of query credits remaining.
    monitored_ips : int
        The number of monitored IPs.
    unlocked_left : int
        The number of unlocks left.
    telnet : bool
        Indicates if Telnet is enabled.

    Raises
    ------
    None

    Returns
    -------
    str
        A string representation of the Shodan API information.
    """

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
        message: str = (
            f"Scan Credits Remaining: {self.scan_credits}\n"
            f"Plan: {self.plan}\n"
            f"Usage Limits:\n"
            f"  {self.usage_limits}\n"
            f"HTTPS: {self.https}\n"
            f"Unlocked: {self.unlocked}\n"
            f"Unlocked left: {self.unlocked_left}\n"
            f"Query Credits: {self.query_credits}\n"
            f"Monitored IPs: {self.monitored_ips}\n"
        )

        return message


class ShodanFilter(BaseModel):
    """
    Represents a filter for Shodan alerts.

    Attributes
    ----------
    ip_network_list : list of netaddr.IPNetwork
        A list of IP networks to be monitored.

    Methods
    -------
    validate_ip(value)
        Validate and convert the input value to a list of IPNetwork objects.
    __len__()
        Returns the number of IP networks in the filter.
    """

    model_config = {"arbitrary_types_allowed": True}
    ip_network_list: list[IPNetwork] = Field(alias="ip", default_factory=list)

    @field_validator("ip_network_list", mode="before")
    @classmethod
    def validate_ip(cls, value):
        """
        Validate and convert the input value to a list of IPNetwork objects.

        Parameters
        ----------
        value : str or list of str
            The input value to be validated and converted.

        Returns
        -------
        list of netaddr.IPNetwork
            A list of IPNetwork objects.

        Raises
        ------
        TypeError
            If the input value is not a string or list of strings.
        """

        if isinstance(value, str):
            return [IPNetwork(value)]

        if isinstance(value, list):
            return [IPNetwork(ip) for ip in value]

        raise TypeError("ip must be a string or list of strings")

    def __len__(self):
        return len(self.ip_network_list)


class ShodanAlert(BaseModel):
    """
    Represents a Shodan alert.

    Attributes
    ----------
    id : str
        The unique identifier for the alert.
    name : str
        The name of the alert.
    filters : ShodanFilter
        The filters associated with the alert.

    Methods
    -------
    size
        Returns the number of IP networks in the alert's filter.
    __str__()
        Returns a string representation of the Shodan alert.
    """

    id: str
    name: str
    filters: ShodanFilter

    @property
    def size(self) -> int:
        return len(self.filters)

    def __str__(self) -> str:
        message: str = (
            f"Name: {self.name}\nID: {self.id}\nSize: {self.size}\nFilters:\n"
        )

        addresses: list = [
            f" IP: {address.ip}" for address in self.filters.ip_network_list
        ]

        return f"{message}{'\n'.join(addresses)}"


class ShodanScanStatus(str, Enum):
    """
    ShodanScanStatus Enum.

    Attributes
    ----------
    SUBMITTING : str
        The scan is being submitted.
    QUEUE : str
        The scan is in the queue.
    PROCESSING : str
        The scan is being processed.
    DONE : str
        The scan is completed.
    """

    SUBMITTING = "SUBMITTING"
    QUEUE = "QUEUE"
    PROCESSING = "PROCESSING"
    DONE = "DONE"


class ShodanScanResult(BaseModel):
    """
    Represents the result of a Shodan scan.

    Attributes
    ----------
    count : int
        The number of IPs in the scan result.
    id : str
        The unique identifier for the scan.
    status : ShodanScanStatus
        The current status of the scan.
    created : str
        The timestamp when the scan was created.

    Raises
    ------
    None

    Returns
    -------
    str
        A string representation of the Shodan scan result.
    """

    count: int
    id: str
    status: ShodanScanStatus
    created: str

    def __str__(self) -> str:
        message: str = (
            f"ID: {self.id}\n"
            f"IP Count: {self.count}\n"
            f"Status: {self.status.value}\n"
            f"Created: {self.created}\n"
        )

        return message
