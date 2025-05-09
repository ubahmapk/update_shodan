from configparser import ConfigParser, DuplicateSectionError
from contextlib import suppress as contextlib_suppress
from pathlib import Path
from sys import stderr
from typing import Annotated

import typer
from httpx import Client as HTTPXClient
from loguru import logger
from netaddr import IPNetwork
from platformdirs import PlatformDirs
from pydantic import ValidationError
from rich import print as rprint
from shodan import APIError as SAPIError
from shodan import Shodan

from update_shodan.__version__ import __version__
from update_shodan.shodan_data import ShodanAlert, ShodanAPIInfo, ShodanScanResult


def set_logging_level(verbosity: int) -> None:
    """
    Set the global logging level.

    Parameters
    ----------
    verbosity : int
        The verbosity level to set for logging.

    Returns
    -------
    None
    """

    # Default level
    log_level = "ERROR"

    if verbosity is not None:
        if verbosity == 1:
            log_level = "INFO"
        elif verbosity > 1:
            log_level = "DEBUG"

    logger.remove(0)
    # noinspection PyUnboundLocalVariable
    logger.add(stderr, level=log_level)


def get_config_file_and_filename() -> tuple[ConfigParser, Path]:
    """
    Return config object for reading / writing, and the config filename.

    Returns
    -------
    tuple of (ConfigParser, Path)
        A tuple containing the ConfigParser object and the Path to the config file.
    """

    config_dir: PlatformDirs = PlatformDirs(appname="update-shodan", ensure_exists=True)
    config_filename: Path = Path(config_dir.user_config_path / "shodan.ini")

    # Save scan ID to app config file
    config: ConfigParser = ConfigParser()
    config.read(config_filename)

    return (config, config_filename)


def shodan_login(shodan_api_key: str) -> Shodan:
    """
    Log in to Shodan with the given API key.

    Parameters
    ----------
    shodan_api_key : str
        The Shodan API key.

    Returns
    -------
    Shodan
        A Shodan client object.
    """

    return Shodan(shodan_api_key)


def retrieve_api_info(shodan_client: Shodan) -> ShodanAPIInfo:
    """
    Retrieve Shodan API information.

    Parameters
    ----------
    shodan_client : Shodan
        The Shodan client object.

    Returns
    -------
    ShodanAPIInfo
        The Shodan API information.

    Raises
    ------
    typer.Exit
        If there is an error retrieving or parsing the Shodan API information.
    """

    try:
        resp: dict = shodan_client.info()
    except SAPIError as e:
        rprint(f"[red]Error getting Shodan API info: {e}[/red]")
        raise typer.Exit(1) from e

    try:
        api_info: ShodanAPIInfo = ShodanAPIInfo(**resp)
    except ValidationError as e:
        rprint(f"[red]Error parsing Shodan API info: {e}[/red]")
        raise typer.Exit(1) from e

    return api_info


def get_current_public_ip(client: HTTPXClient) -> IPNetwork:
    """
    Get the current public IP address.

    Parameters
    ----------
    client : HTTPXClient
        The HTTPX client object.

    Returns
    -------
    IPNetwork
        The current public IP address as an IPNetwork object.
    """

    current_ip: str = client.get("https://api.ipify.org").text
    logger.debug(f"Current IP: {current_ip}")
    current_ip_network = IPNetwork(current_ip)

    return current_ip_network


def list_shodan_alerts(shodan_client: Shodan) -> list[ShodanAlert]:
    """
    List all Shodan alerts.

    Parameters
    ----------
    shodan_client : Shodan
        The Shodan client object.

    Returns
    -------
    list of ShodanAlert
        List of ShodanAlert objects.
    """

    logger.debug("Shodan Client Alerts:")
    logger.debug(f"{shodan_client.alerts()}")

    try:
        alerts: list[ShodanAlert] = [
            ShodanAlert(**alert) for alert in shodan_client.alerts()
        ]
    except SAPIError as e:
        print("Error listing Shodan alerts. Please check your API key and try again.")
        raise typer.Exit(1) from e

    return alerts


def print_shodan_alerts(shodan_alerts: list[ShodanAlert]) -> None:
    """
    Print a list of Shodan alerts.

    Parameters
    ----------
    shodan_alerts : list of ShodanAlert
        List of ShodanAlert objects.

    Returns
    -------
    None
    """

    for alert in shodan_alerts:
        print(alert)

    return None


def find_home_network_shodan_alert(
    shodan_alerts: list[ShodanAlert],
) -> ShodanAlert:
    """
    Find the Shodan alert with the name "Home Network".

    Parameters
    ----------
    shodan_alerts : list of ShodanAlert
        The list of Shodan alerts.

    Returns
    -------
    ShodanAlert
        The Shodan alert with the name "Home Network".

    Raises
    ------
    ValueError
        If no alert with the name "Home Network" is found.
    """

    for alert in shodan_alerts:
        logger.debug(f"alert name: {alert.name}")
        if alert.name == "Home Network":
            logger.debug("Found Home Network alert")
            logger.debug(f"{alert=}")
            return alert

    print("No Home Network alert found")
    raise typer.Exit(1)


def public_ip_has_changed(current_ip: IPNetwork, shodan_alert: ShodanAlert) -> bool:
    """
    Check if the public IP has changed.

    Parameters
    ----------
    current_ip : IPNetwork
        The current public IP address.
    shodan_alert : ShodanAlert
        The Shodan alert object.

    Returns
    -------
    bool
        True if the public IP has changed, False otherwise.
    """

    logger.debug(
        f"IP Networks in current alert: {shodan_alert.filters.ip_network_list}"
    )

    return current_ip not in shodan_alert.filters.ip_network_list


def update_shodan_alert(
    shodan_client: Shodan, shodan_alert: ShodanAlert, current_ip: IPNetwork
) -> None:
    """
    Update the Shodan alert with the current IP address.

    Parameters
    ----------
    shodan_client : Shodan
        The Shodan client object.
    shodan_alert : ShodanAlert
        The Shodan alert object to be updated.
    current_ip : IPNetwork
        The current public IP address.

    Returns
    -------
    None
    """

    logger.debug(f"Updating Shodan alert {shodan_alert.id} with {current_ip}")

    try:
        shodan_client.edit_alert(shodan_alert.id, [current_ip.__str__()])
    except SAPIError as e:
        rprint(f"[red]Error updating Shodan alert: {e}[/red]")
        raise typer.Exit(1) from e

    return None


def save_scan_id_to_configfile(scan_id: str) -> None:
    """
    Save Shodan Scan ID to config file.

    Parameters
    ----------
    scan_id : str
        The Shodan scan ID to save.

    Returns
    -------
    None
    """

    config, config_filename = get_config_file_and_filename()

    # Add Shodan section, if it doesn't already exist
    with contextlib_suppress(DuplicateSectionError):
        config.add_section("shodan")

    config["shodan"]["scan_id"] = scan_id
    try:
        with open(config_filename, "w") as configfile:
            config.write(configfile)
        rprint("[green]Saved scan ID to config file[/green]")
    except OSError as e:
        rprint(f"[red]Error writing to config file[/red]\n{e}")

    return None


def start_new_shodan_scan(shodan_client: Shodan, current_ip: IPNetwork) -> None:
    """
    Start a new Shodan scan with the current IP address.

    Parameters
    ----------
    shodan_client : Shodan
        The Shodan client object.
    current_ip : IPNetwork
        The current public IP address.

    Returns
    -------
    None
    """

    try:
        results: dict = shodan_client.scan(current_ip.__str__())
    except SAPIError as e:
        rprint(f"[red]Error starting Shodan scan: {e}[/red]")
        raise typer.Exit(1) from e

    logger.debug(f"Full results listing: {results}")

    save_scan_id_to_configfile(results["id"])

    print(f"Started scan: {results['id']}")
    print(f"Credits left: {results['credits_left']}")
    print()

    return None


def read_shodan_scan_id_from_config() -> str:
    """
    Read the Shodan scan ID from the config file.

    Returns
    -------
    str
        The Shodan scan ID.

    Raises
    ------
    typer.Exit
        If no scan ID is found in the config file.
    """

    config, _ = get_config_file_and_filename()

    try:
        scan_id: str = config["shodan"]["scan_id"]
    except KeyError as ke:
        rprint("[red]No scan ID found in config file[/red]")
        raise typer.Exit(1) from ke

    return scan_id


def print_shodan_scan_results(shodan_client: Shodan, scan_id: str) -> None:
    """
    Print the results of a Shodan scan.

    Parameters
    ----------
    shodan_client : Shodan
        The Shodan client object.
    scan_id : str
        The Shodan scan ID.

    Returns
    -------
    None
    """

    try:
        results: dict = shodan_client.scan_status(scan_id)
    except SAPIError as e:
        rprint(f"[red]Error getting Shodan scan results: {e}[/red]")
        raise typer.Exit(1) from e

    print(ShodanScanResult(**results))

    return None


app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def version_callback(value: bool) -> None:
    """
    Print script version and exit.

    Parameters
    ----------
    value : bool
        The value indicating whether to print the version.

    Returns
    -------
    None
    """

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
    print_alerts: Annotated[
        bool, typer.Option("--print", "-p", help="Print Shodan alerts and exit")
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
    show_scan_status: Annotated[
        bool, typer.Option("--status", "-s", help="Show status of last scan")
    ] = False,
    scan_id: Annotated[
        str,
        typer.Option(
            "--scan-id",
            "-i",
            help="Previous Scan ID (Will read from config, if not passed as an option)",
        ),
    ] = "",
    api_check: Annotated[
        bool, typer.Option("--api-check", "-a", help="Print Shodan API Usage Limits")
    ] = False,
    verbosity: Annotated[
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
) -> None:
    """
    Command line interface for updating Shodan alerts for the home network.

    This function retrieves the current public IP address, checks if it has changed,
    and updates the Shodan alert for the home network if necessary. It also initiates
    a new Shodan scan if the IP address has changed.
    """

    set_logging_level(verbosity)

    if not shodan_api_key:
        rprint("[red]SHODAN_API_KEY environment variable not set[/red]")
        raise typer.Exit(1)

    shodan_client = shodan_login(shodan_api_key)
    client = HTTPXClient()

    if show_scan_status:
        # Read the Scan ID from config, if not passed via CLI
        if not scan_id:
            scan_id = read_shodan_scan_id_from_config()

        print_shodan_scan_results(shodan_client, scan_id)

        raise typer.Exit(0)

    if api_check:
        api_info: ShodanAPIInfo = retrieve_api_info(shodan_client)
        print(api_info)
        raise typer.Exit(0)

    current_ip = get_current_public_ip(client)

    shodan_alerts = list_shodan_alerts(shodan_client)

    if print_alerts:
        print_shodan_alerts(shodan_alerts)
        raise typer.Exit(0)

    home_alert: ShodanAlert = find_home_network_shodan_alert(shodan_alerts)

    if clean and home_alert.size > 1:
        print("Removing all other IPs from the Shodan alert")
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
        print("Updating Shodan alert")
        update_shodan_alert(shodan_client, home_alert, current_ip)
        rprint("[green]Success[/green]")
        if not no_scan:
            print()
            print("Starting new Shodan scan")
            start_new_shodan_scan(shodan_client, current_ip)

    return None


if __name__ == "__main__":
    app()
