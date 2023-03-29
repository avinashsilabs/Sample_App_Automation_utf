import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116JoinFeatureBitMap, RS9116Band, RS9116CustomFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    '''Test plan executes power test cases and measure current with power save mode 2 lp with max psp and enhanced max psp'''

    Author: Aravind
"""


class Pingthread(ThreadBase):
    def __init__(self, device_ip=None, ping_count=None):
        super().__init__()
        self.device_ip = device_ip
        self.ping_count = ping_count

    def run(self):
        status = ping(self.device_ip, self.ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
    },
)
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_pwr_mode2_lp_mode_listen_interval_C40158(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer,
                                                       power_meter, request, rs_helper, utf_constants):
    with TimeMeasurer() as t:
        ping_count = 120
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode2 lp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)
        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        rs_helper.get_power_value(power_meter=power_meter)
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
    },
)
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_pwr_mode2_lp_mode_listen_interval_C113952(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer,
                                                        power_meter, request, rs_helper, utf_constants):
    with TimeMeasurer() as t:
        ping_count = 120
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode2 lp enhanced maxpsp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 1)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")

        rs_helper.get_power_value(power_meter=power_meter)
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
