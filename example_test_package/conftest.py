from utf.utils.test_management.utils import generate_base_test_definitions_yaml
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
        yield fw_mgr

        #load default firmware
        fw_mgr.load_default_firmware_at_test_case_teardown(app_name)


@pytest.fixture(autouse=True, scope='session')
def store_environment_info(request, harness: Harness):
    if os.environ.get("GIT_BRANCH") is not None:
        request.config._metadata['Milestone'] = os.environ["GIT_BRANCH"]
    else:
        request.config._metadata['Milestone'] = os.environ["MILESTONE"]
    request.config._metadata['DUT Firmware Version'] = parse_version()
    dut = UtfConfig.instance().defaults.get("dut", {})
    dut_type = UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("type", "")
    request.config._metadata['DUT Type'] = dut_type
    dut_subtype = UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("subtype", "")
    request.config._metadata['DUT Sub Type'] = dut_subtype
    access_point = UtfConfig.instance().defaults.get("wifi_access_point")
    access_point_type = UtfConfig.instance().data.get("devices", {}).get(access_point, {}).get("interfaces", {}).get("wifi", {}).get("type", "")
    access_point_type = access_point_type.split(".")[-1]
    request.config._metadata['Access point Type'] = access_point_type


def pytest_collection_modifyitems(config, items):
    if config.option.collectonly:
        generate_base_test_definitions_yaml(os.getcwd(), items)
