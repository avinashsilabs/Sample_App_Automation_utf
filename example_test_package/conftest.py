import time

from utf import TestResultsModelAttrs, TestUserPropertiesSource
from utf.apis import extract_test_case_id
from utf.env_settings import EnvironSettings
from utf.utils import (
    is_publish_test_results_enabled,
    is_test_results_source_api_enabled,
)
from utf.utils.test_management.test_definition_utils import (
    generate_base_test_definitions_yaml,
)
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
from utf_wiseconnect.utils.sl_collections import SLCollections
from utf_wiseconnect.utils.rs_helper_commands_ble import RSHelperCommandsBle
import utf.utils.commander as commander
from utf_wiseconnect.devices.rs911x import RS911X

last_loaded_custom_app_name = None
last_test_mode = None
default_test_mode = None


def logger():
    return get_logger(__name__)


@pytest.fixture(autouse=True, scope="module")
def reset_wiseconnect_duts(request, harness):
    """
    This fixture creates devices from configuration specified under defaults and under
    wiseconnect_duts section and calls reset on each device at a module level

    Args:
        request: ``FixtureRequest`` This object provides information of requesting test case
        harness: ``Harness`` This object represents test bed configuration

    Returns:
        None
    """
    try:
        wiseconnect_duts = harness.create_devices_for_role("wiseconnect_duts", request)
        for dut in wiseconnect_duts:
            try:
                logger().info(
                    f"Calling device reset from module level fixture for device '{dut.name}'"
                )
                dut.reset()
                time.sleep(3)
            except Exception as e:
                logger().error(
                    f"Failed to reset from module level fixture for device '{dut.name}' - {e}"
                )
    except Exception as e:
        logger().error(f"Failed to reset from module level fixture - {e}")


@pytest.fixture()
def wiseconnect_duts(
    request: pytest.FixtureRequest, harness
) -> Generator[List[Device], None, None]:
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


@pytest.fixture(autouse=True, scope="function")
def roll_back_to_default_firmware(request, wiseconnect_duts):
    global last_loaded_custom_app_name
    if (
        "firmware_loader" not in request.fixturenames
        and last_loaded_custom_app_name is not None
    ):
        fw_mgr = FirmwareManager.get_instance()
        fw_mgr.roll_back_to_default_firmware(
            last_loaded_custom_app_name, wiseconnect_duts
        )
        last_loaded_custom_app_name = None


@pytest.fixture(autouse=True, scope="session")
def store_environment_info(request, harness: Harness):
    request.config._metadata["Milestone"] = os.environ["MILESTONE"]
    manifest_file: str = request.config.getoption("manifest")
    if manifest_file is not None:
        request.config._metadata["DUT Firmware Version"] = parse_version(manifest_file)
    else:
        request.config._metadata["DUT Firmware Version"] = "Firmware not loaded"
    dut = UtfConfig.instance().defaults.get("dut", {})
    dut_type = UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("type", "")
    request.config._metadata["DUT Type"] = dut_type
    dut_subtype = (
        UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("subtype", "")
    )
    request.config._metadata["DUT Sub Type"] = dut_subtype
    access_point = UtfConfig.instance().defaults.get("wifi_access_point")
    access_point_type = (
        UtfConfig.instance()
        .data.get("devices", {})
        .get(access_point, {})
        .get("interfaces", {})
        .get("wifi", {})
        .get("type", "")
    )
    access_point_type = access_point_type.split(".")[-1]
    request.config._metadata["Access point Type"] = access_point_type
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

@pytest.fixture()
def sl_collections(request):
    yield SLCollections.create_instance()


@pytest.fixture()
def rs_helper_ble(request):
    yield RSHelperCommandsBle.create_instance()


@pytest.fixture(autouse=True, scope="function")
def reset_on_test_mode_change(request, wiseconnect_duts, harness):
    """
    This fixture checks for change in test mode between last executed test case and current test case
    and does device reset on device if there is change

    Args:
        request: ``FixtureRequest`` This object provides context of requesting test case
        wiseconnect_duts: ``List[Device]`` list of devices on which reset happens
        harness: ``Harness`` This object represents test bed configuration

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
    dut = harness.create_device(current_test_mode)
    if isinstance(wiseconnect_duts[0], RS911X):
        wiseconnect_duts[0] = dut
    else:
        wiseconnect_duts[1] = dut
    if current_test_mode != last_test_mode:
        for device in wiseconnect_duts:
            device.reset()
        last_test_mode = current_test_mode


@pytest.hookimpl(trylast=True, hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    if is_publish_test_results_enabled() and is_test_results_source_api_enabled():
        module_name = UtfConfig.instance().defaults.get("dut")
        settings = EnvironSettings()
        case_id = extract_test_case_id(item.originalname)
        tool_chain = "GCC 10.3.1"
        if settings.TOOL_CHAIN:
            tool_chain = settings.TOOL_CHAIN

        custom_values = {
            TestResultsModelAttrs.module_name: module_name,
            TestResultsModelAttrs.tool_chain: tool_chain,
        }
        item.user_properties.append((TestUserPropertiesSource.TEST_CASE_ID, case_id))
        item.user_properties.append(
            (TestUserPropertiesSource.TEST_CUSTOM_INFO, custom_values)
        )
    yield
