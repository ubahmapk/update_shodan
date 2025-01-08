from typing import Annotated

import typer
from httpx import Client as HTTPXClient
from netaddr import IPNetwork
from rich import print as rprint
from shodan import APIError as SAPIError
from shodan import Shodan

from update_shodan.__version__ import __version__
from update_shodan.shodan_data import ShodanAlert


def shodan_login(shodan_api_key: str) -> Shodan:
    """
    Log in to Shodan with the given API key.

    Args:
        shodan_api_key (str): The Shodan API key.

    Returns:
        A Shodan client object.
    """

    return Shodan(shodan_api_key)


def get_current_public_ip(client: HTTPXClient) -> IPNetwork:
    """
    Get the current public IP address.

    Args:
        client: The HTTPX client object.

    Returns:
        The current public IP address as an IPNetwork object.
    """
    return IPNetwork(client.get("https://api.ipify.org").text)


def list_shodan_alerts(shodan_client: Shodan) -> list[ShodanAlert]:
    """
    List all Shodan alerts.

    Args:
        shodan_client: The Shodan client object.

    Returns:
        List of ShodanAlert objects.
    """

    try:
        alerts: list[ShodanAlert] = [
            ShodanAlert(**alert) for alert in shodan_client.alerts()
        ]
    except SAPIError as e:
        print(f"Error listing Shodan alerts. Please check your API key and try again.")
        raise typer.Exit(1) from e

    return alerts


def print_shodan_alerts(shodan_alerts: list[ShodanAlert]) -> None:
    """
    Print a list of Shodan alerts.

    Args:
        shodan_alerts (list[ShodanAlert]): List of ShodanAlert objects.

    Returns:
        None
    """
    for alert in shodan_alerts:
        print(f"ID: {alert.id}")
        print(f"Name: {alert.name}")
        print(f"Size: {alert.size}")
        print(f"Filters:")
        for address in alert.filters.ip_network_list:
            print(f"  IP: {address.ip}")

    return None


def find_home_network_shodan_alert(
    shodan_alerts: list[ShodanAlert],
) -> ShodanAlert:
    """
    Find the Shodan alert with the name "Home Network".

    Args:
        shodan_alerts (list[ShodanAlert]): The list of Shodan alerts.

    Returns:
        ShodanAlert: The Shodan alert with the name "Home Network".

    Raises:
        ValueError: If no alert with the name "Home Network" is found.
    """
    for alert in shodan_alerts:
        if alert.name == "Home Network":
            return alert

    print("No Home Network alert found")
    raise typer.Exit(1)


def public_ip_has_changed(current_ip: IPNetwork, shodan_alert: ShodanAlert) -> bool:
    """
    Check if the current public IP address is different from the IP address
    stored in the given Shodan alert.

    Args:
        current_ip: The current public IP address.
        shodan_alert: The Shodan alert to check against.

    Returns:
        True if the current IP address is different from the IP address
        currently in the alert, False otherwise.
    """
    if current_ip in shodan_alert.filters.ip_network_list:
        return False

    return True


def update_shodan_alert(
    shodan_client: Shodan, shodan_alert: ShodanAlert, current_ip: IPNetwork
) -> None:
    """
    Update the given Shodan alert with the current IP address.

    Args:
        shodan_client: A Shodan client object.
        shodan_alert: The Shodan alert to update.
        current_ip: The current public IP address.

    Returns:
        None
    """
    try:
        shodan_client.edit_alert(shodan_alert.id, [current_ip.__str__()])
    except SAPIError as e:
        raise typer.Abort(f"Error updating Shodan alert: {e}") from e

    return None


def start_new_shodan_scan(shodan_client: Shodan, current_ip: IPNetwork) -> None:
    """
    Start a new Shodan scan for the given IP address.

    Args:
        shodan_client: A Shodan client object.
        current_ip: The current public IP address.

    Returns:
        None
    """
    try:
        results: dict = shodan_client.scan(current_ip.__str__())
    except SAPIError as e:
        raise typer.Abort(f"Error starting Shodan scan: {e}") from e

    print(f'Started scan: {results["id"]}')
    print(f'Credits left: {results["credits_left"]}')
    print()

    return None


app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def version_callback(value: bool) -> None:
    if value:
        print(f"update-shodan version {__version__}")

        raise typer.Exit(0)


@app.command()
def cli(
    shodan_api_key: Annotated[
        str,
        typer.Argument(envvar="SHODAN_API_KEY", help="Shodan API key"),
    ] = "",
    dry_run: Annotated[bool, typer.Option("--dry-run", "-d", help="Dry run")] = False,
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Verbose mode. Repeat for increased verbosity",
        ),
    ] = 0,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            show_default=False,
        ),
    ] = False,
    clean: Annotated[
        bool,
        typer.Option(
            "--clean", "-c", help="Remove all other IPs from the Shodan alert"
        ),
    ] = False,
    no_scan: Annotated[
        bool, typer.Option("--no-scan", "-n", help="Don't start a new Shodan scan")
    ] = False,
) -> None:
    """
    Command line interface for updating Shodan alerts for the home network.

    This function retrieves the current public IP address, checks if it has changed,
    and updates the Shodan alert for the home network if necessary. It also initiates
    a new Shodan scan if the IP address has changed.
    """

    if not shodan_api_key:
        raise typer.Abort("SHODAN_API_KEY environment variable not set")

    shodan_client = shodan_login(shodan_api_key)
    client = HTTPXClient()
    current_ip = get_current_public_ip(client)

    shodan_alerts = list_shodan_alerts(shodan_client)

    # print_shodan_alerts(shodan_alerts)

    home_alert: ShodanAlert = find_home_network_shodan_alert(shodan_alerts)

    if clean and home_alert.size > 1:
        print(f"Removing all other IPs from the Shodan alert")
        if not dry_run:
            update_shodan_alert(shodan_client, home_alert, current_ip)

    if not public_ip_has_changed(current_ip, home_alert):
        print()
        rprint(f"[green]Current IP {current_ip} has not changed[/green]")
        print()
        raise typer.Exit(0)

    print()
    rprint(f"[red]IP has changed ({current_ip})[/red]")
    print()

    if not dry_run:
        print(f"Updating Shodan alert")
        update_shodan_alert(shodan_client, home_alert, current_ip)
        rprint(f"[green]Success[/green]")
        if not no_scan:
            print()
            print(f"Starting new Shodan scan")
            start_new_shodan_scan(shodan_client, current_ip)

    return None


if __name__ == "__main__":
    app()
