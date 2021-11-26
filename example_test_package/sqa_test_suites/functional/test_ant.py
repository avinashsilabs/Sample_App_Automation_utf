import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger

def logger():
    return get_logger(__name__)

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Use Ant supported Firmware and the EVK board(v1.5)
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
            }
        )
    ]
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# The test case initiates the ant service in module
def test_ant_init(wifi_dut):
    with TimeMeasurer() as t:
        # This API initiates the Ant in dut
        wifi_dut.interfaces.wifi.ant_init(ant_cmd=12, ant_cmd_1=3, ant_cmd_2=1, ant_cmd_3=75, ant_cmd_4=0, ant_cmd_5=0, ant_cmd_resp=0)
    logger().info(f"Associated in {t.duration} seconds")