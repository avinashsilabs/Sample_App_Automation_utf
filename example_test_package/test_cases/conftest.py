from utf_wiseconnect.interfaces.web.fixtures import *  # NOSONAR
import pytest
from utf.utils.firmware_manager import FirmwareManager
from utf.devices import Device
from typing import Generator, List
from utf.utils.logger import get_logger


@pytest.fixture()
def wiseconnect_duts(request: pytest.FixtureRequest, harness) -> Generator[List[Device], None, None]:
    wiseconnect_duts = harness.create_devices_for_role(request.fixturename, request)
    yield wiseconnect_duts

    # Clean up WiseConnect Devices
    get_logger().info(f"Cleaning up WiseConnect DUTs")


@pytest.fixture()
def firmware_loader(request, wiseconnect_duts):
    for mark in request.node.iter_markers("firmware_app"):
        app_name = mark.args[0]
        fw_mgr = FirmwareManager.get_instance()
        if fw_mgr is not None:
            fw_mgr.load_app_firmware(app_name, wiseconnect_duts)
        yield fw_mgr

        #load default firmware
        fw_mgr.load_app_default_firmware(app_name, wiseconnect_duts)
