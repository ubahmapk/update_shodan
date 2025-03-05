import pytest
import typer
from netaddr import IPNetwork

from update_shodan.cli import find_home_network_shodan_alert, public_ip_has_changed
from update_shodan.shodan_data import ShodanAlert


@pytest.fixture
def alerts_list() -> list[ShodanAlert]:
    # Create a list with multiple alerts, one of which is "Home Network"
    alert1_data: dict = {
        "name": "Test Alert",
        "filters": {"ip": "1.2.3.5/32"},
        "id": "1",
        "size": 1,
    }

    alert2_data: dict = {
        "name": "Home Network",
        "filters": {"ip": "1.2.3.4/32"},
        "id": "2",
        "size": 1,
    }

    alert3_data: dict = {
        "name": "Other Alert",
        "filters": {"ip": "1.2.3.6/32"},
        "id": "3",
        "size": 1,
    }

    alert4_data: dict = {
        "name": "Empty Alert",
        "filters": {},
        "id": "4",
        "size": 0,
    }

    alert1: ShodanAlert = ShodanAlert(**alert1_data)
    alert2: ShodanAlert = ShodanAlert(**alert2_data)
    alert3: ShodanAlert = ShodanAlert(**alert3_data)
    alert4: ShodanAlert = ShodanAlert(**alert4_data)

    return [alert1, alert2, alert3, alert4]


def test_find_home_network_alert_success(alerts_list: list[ShodanAlert]):
    home_alert = find_home_network_shodan_alert(alerts_list)
    assert home_alert.name == "Home Network"


def test_find_home_network_alert_failure(alerts_list: list[ShodanAlert]):
    # Create a list without a "Home Network" alert
    alerts = [alert for alert in alerts_list if alert.name != "Home Network"]

    with pytest.raises(typer.Exit) as excinfo:
        find_home_network_shodan_alert(alerts)
    assert excinfo.value.exit_code == 1


def test_public_ip_has_changed_no_change(alerts_list: list[ShodanAlert]):
    # current IP is in the alert's network list
    current_ip = IPNetwork("1.2.3.4/32")
    assert public_ip_has_changed(current_ip, alerts_list[1]) is False


def test_public_ip_has_changed_change(alerts_list: list[ShodanAlert]):
    # current IP is not in the alert's network list
    current_ip = IPNetwork("1.2.3.4/32")
    assert public_ip_has_changed(current_ip, alerts_list[0]) is True


def test_public_ip_has_changed_empty_network_list(alerts_list: list[ShodanAlert]):
    # When no IP networks are present in the alert, the function should report a change
    current_ip = IPNetwork("1.2.3.4/32")
    assert public_ip_has_changed(current_ip, alerts_list[3]) is True
