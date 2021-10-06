import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
from devices.rs911x import RS9116BTFeatureBitMap
import time
import os

def logger():
    return get_logger(__name__)

# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#             "oper_mode": 0,
#             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
#             "bt_features": RS9116BTFeatureBitMap.Default |
#                            RS9116BTFeatureBitMap.A2DPProfileEnable |
#                            RS9116BTFeatureBitMap.A2DPSourceRoleEnable
#         }
# )
def test_bt_a2dp_dut_as_src(http_server):
    # if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
    #     raise NotImplementedError(
    #         "This test case is only currently implemented for SAPI"
    #     )
    logger().info("Test case started...")
    with TimeMeasurer() as t:
        assert http_server.interfaces.http.started
        time.sleep(15)
    logger().info(f"Scan in {t.duration} seconds")