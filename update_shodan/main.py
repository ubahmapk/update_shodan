from httpx import Client
from netaddr import IPAddress
from shodan import Shodan

from update_shodan.shodan_data import ShodanAlert


def get_shodan_client(shodan_api_key: str) -> Shodan:
    return Shodan(shodan_api_key)


def get_current_public_ip(client: Client) -> IPAddress:
    return IPAddress(client.get("https://api.ipify.org").text)


def list_shodan_alerts(shodan_client: Shodan) -> list[ShodanAlert]:
    return [ShodanAlert(**alert) for alert in shodan_client.alerts()]


def print_shodan_alerts(shodan_alerts: list[ShodanAlert]) -> None:
    """Print the list of alerts in a user friendly format."""
    for alert in shodan_alerts:
        print(f"ID: {alert.id}")
        print(f"Name: {alert.name}")
        print(f"Size: {alert.size}")
        print(f"Filters:")
        for address in alert.filters.ip_network_list:
            print(f"  IP: {address.ip}")

    return None


def update_shodan_alert(
    shodan_api_key: str,
    shodan_alert_id: int,
    current_public_ip: IPAddress,
    shodan_client: Shodan,
) -> None:
    shodan_alert = shodan_client.alerts[shodan_alert_id]
    shodan_alert.update(
        {
            "ip": str(current_public_ip),
            "status": "open",
        }
    )
