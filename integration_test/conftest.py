import os
import pytest
from _pytest.config import Config
import utf.utils.commander as commander
from time import sleep
from utf.utils.firmware_manager import FirmwareManager

# import fixtures defined in other modules so that they can be used in all tests without explicitly importing them
from utf.utils.fixtures import *  # NOSONAR
from utf.interfaces.wifi.fixtures import *  # NOSONAR
from utf.interfaces.bluetooth.fixtures import *  # NOSONAR
from utf.interfaces.iperf.fixtures import *  # NOSONAR
from utf.utils.fixtures import HarnessCache
from utf.utils.logger import get_logger
from utf.utils.test_management.test_definition_utils import generate_base_test_definitions_yaml

last_loaded_custom_app_name = None

@pytest.fixture(autouse=True)
def reset_dut():
    commander.reset_device()
    sleep(5)


@pytest.fixture(params=["rs9116_sapi", "rs9116_at"])
def parameterize_dut(harness, request):
    """
    Parameterizes the dut used by applying the 'dut' marker with the name of each dut to test with.
    """
    request.applymarker(pytest.mark.dut(request.param))


@pytest.fixture(params=["raspi_wifi", "dlink810_ap", "asus_rt_ax3000_ap"])
def parameterize_access_point(request):
    """
    Parameterizes the access point used by applying the 'wifi_access_point' marker with the name of each
    access point to test with.
    """
    request.applymarker(pytest.mark.wifi_access_point(request.param))


@pytest.fixture()
def wiseconnect_duts(request: pytest.FixtureRequest, harness) -> Generator[List[Device], None, None]:
    """
    This fixture creates devices from configuration specified under defaults and under wiseconnect_duts section

    Args:
        request: ``FixtureRequest`` This object provides information of requesting test case
        harness: ``Harness`` This object represents test bed configuration

    Returns:
        None
    """
    wiseconnect_duts = harness.create_devices_for_role(request.fixturename, request)
    yield wiseconnect_duts

    # Clean up WiseConnect Devices
    get_logger().info(f"Cleaning up WiseConnect DUTs")


@pytest.fixture()
def firmware_loader(request, wiseconnect_duts):
    """
    This fixture loads firmware on devices from configuration specified in manifest file under firmware_applications
    section under specified marker on test case

    Args:
        request: ``FixtureRequest`` This object provides context of requesting test case
        wiseconnect_duts: ``List[Device]`` list of devices on which firmware is loaded

    Returns:
        None
    """
    for mark in request.node.iter_markers("firmware_app"):
        app_name = mark.args[0]
        fw_mgr = FirmwareManager.get_instance()
        if fw_mgr is not None:
            fw_mgr.load_app_firmware(app_name, wiseconnect_duts)
            global last_loaded_custom_app_name
            last_loaded_custom_app_name = app_name
        yield fw_mgr

@pytest.fixture(autouse=True, scope='function')
def roll_back_to_default_firmware(request, wiseconnect_duts):
    global last_loaded_custom_app_name
    if 'firmware_loader' not in request.fixturenames and last_loaded_custom_app_name is not None:
        fw_mgr = FirmwareManager.get_instance()
        fw_mgr.roll_back_to_default_firmware(last_loaded_custom_app_name, wiseconnect_duts)
        last_loaded_custom_app_name = None

MARKERS = [
    "wiseconnect_duts",
    "firmware_loader"
]


def pytest_configure(config: Config) -> None:
    for marker in MARKERS:
        config.addinivalue_line("markers", marker)


def pytest_collection_modifyitems(config, items):
    if config.option.collectonly:
        generate_base_test_definitions_yaml(os.getcwd(), items)