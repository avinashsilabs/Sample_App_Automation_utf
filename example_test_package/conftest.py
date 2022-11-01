from utf.utils.test_management.test_definition_utils import generate_base_test_definitions_yaml
from utf_wiseconnect.interfaces.web.fixtures import *  # NOSONAR
import pytest
import os
from utf.utils.firmware_manager import FirmwareManager
from utf.devices import Device
from typing import Generator, List
from utf.utils.logger import get_logger
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utf_config import UtfConfig
from utf.utils.fixtures import harness
from utf.harness.harness import Harness
from utf_wiseconnect.utils.rs_helper_commands import RSHelperCommands
import utf.utils.commander as commander
from utf_wiseconnect.devices.rs911x import RS9116

last_loaded_custom_app_name = None
last_test_mode = None
default_test_mode = None


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
    dut = wiseconnect_duts[0] if isinstance(wiseconnect_duts[0], RS9116) else wiseconnect_duts[1]
    wifi_interface = dut.create_interface("wifi")
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


@pytest.fixture(autouse=True, scope='session')
def store_environment_info(request, harness: Harness):
    if os.environ.get("GIT_BRANCH") is not None:
        request.config._metadata['Milestone'] = os.environ["GIT_BRANCH"]
    else:
        request.config._metadata['Milestone'] = os.environ["MILESTONE"]
    manifest_file: str = request.config.getoption("manifest")
    if manifest_file is not None:
        request.config._metadata['DUT Firmware Version'] = parse_version(manifest_file)
    else:
        request.config._metadata['DUT Firmware Version'] = "Firmware not loaded"
    dut = UtfConfig.instance().defaults.get("dut", {})
    dut_type = UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("type", "")
    request.config._metadata['DUT Type'] = dut_type
    dut_subtype = UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("subtype", "")
    request.config._metadata['DUT Sub Type'] = dut_subtype
    access_point = UtfConfig.instance().defaults.get("wifi_access_point")
    access_point_type = UtfConfig.instance().data.get("devices", {}).get(access_point, {}).get("interfaces", {}).get("wifi", {}).get("type", "")
    access_point_type = access_point_type.split(".")[-1]
    request.config._metadata['Access point Type'] = access_point_type
    global default_test_mode
    default_test_mode = UtfConfig.instance().defaults.get("dut")
    global last_test_mode
    last_test_mode = default_test_mode


def pytest_collection_modifyitems(config, items):
    if config.option.collectonly:
        generate_base_test_definitions_yaml(os.getcwd(), items)


@pytest.fixture()
def rs_helper(request):
    yield RSHelperCommands.create_instance()


@pytest.fixture(autouse=True, scope='function')
def reset_on_test_mode_change(request, wiseconnect_duts):
    """
    This fixture checks for change in test mode between last executed test case and current test case
    and does commander, soft reset on device if there is change

    Args:
        request: ``FixtureRequest`` This object provides context of requesting test case
        wiseconnect_duts: ``List[Device]`` list of devices on which reset happens

    Returns:
        None

    """
    markers_list = list(request.node.iter_markers(name="dut"))
    if markers_list:
        marker = markers_list[0]
        current_test_mode = marker.args[0]
    else:
        current_test_mode = default_test_mode
    global last_test_mode
    if current_test_mode != last_test_mode:
        commander.reset_device()
        for device in wiseconnect_duts:
            device.reset()
        last_test_mode = current_test_mode
