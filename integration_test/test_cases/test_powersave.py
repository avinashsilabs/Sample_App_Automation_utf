import pytest
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116FeatureBitMap

# Mark all tests in this module with 'framework_integration_test'
# and use fixtures parameterize_dut and parameterize_access_point
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
        },
    ),
    pytest.mark.wifi_access_point("raspi_wifi")
]

@pytest.mark.dut("rs9116_sapi")
@pytest.mark.test_src_map_id('SM11928')
def test_power_save(wifi_dut, wifi_networked_dut, logger):

    awake = wifi_networked_dut.interfaces.wifi.get_wake_gpio()
    assert awake

    wifi_networked_dut.interfaces.wifi.set_sleep_gpio(True)
    wifi_networked_dut.interfaces.wifi.power_save(2)

    # after power save mode enabled, DUT should confirm state by setting wake GPIO low
    # (except for DTIM interval)
    awake_sum = 0
    for _ in range(0, 20):
        awake_sum += 1 if wifi_networked_dut.interfaces.wifi.get_wake_gpio() else 0
    assert awake_sum <= 5, "DUT did not go to sleep"

    # Upon wake request from the host, DUT should confirm leaving of low power state by
    # setting wake GPIO high
    wifi_networked_dut.interfaces.wifi.set_sleep_gpio(False)
    sw = Stopwatch()
    while sw.elapsed_sec < 5:
        # wait for DUT to assert wake pin 5 consecutive iterations
        for _ in range(0, 5):
            if not wifi_networked_dut.interfaces.wifi.get_wake_gpio():
                break
        else:
            break
    else:
        raise AssertionError("DUT did not leave sleep state")

    # after power save mode is re-enabled by asserting sleep GPIO, DUT should confirm state by setting wake GPIO low
    # (except for DTIM interval)
    wifi_networked_dut.interfaces.wifi.set_sleep_gpio(True)
    awake_sum = 0
    for _ in range(0, 20):
        awake_sum += 1 if wifi_networked_dut.interfaces.wifi.get_wake_gpio() else 0
    assert awake_sum <= 5, "DUT did not go to sleep"
