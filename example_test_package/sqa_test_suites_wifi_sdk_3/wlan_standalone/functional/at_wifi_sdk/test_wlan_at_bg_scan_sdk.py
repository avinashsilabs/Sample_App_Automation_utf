import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect_3.tests.devices.si91x import Si91xOperatingMode
from utf.interfaces.wifi import WlanError
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_at_cli import SlNetInterfaceType, SlNetProfileId


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Enable Background scan
        5. Validate Probe response & HT information, BG scan on primary, non US & DFS channel etc. via sniffer with
           different mode/channels 

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC 

    Author: Shaik Abdul Azeez
"""


def get_channel_bitmap_2g4(channels):
    bitmap = 0
    for ch in channels:
        if 1 <= ch <= 14:
            bitmap |= (1 << (ch - 1))
    return bitmap


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, time_period=None,
                 test_name=None, sl_collections=None, bgscan_kwargs=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.bgscan_kwargs = bgscan_kwargs or {}

    def run(self):
        try:

            self.wifi_dut.interfaces.wifi.advance_scan(trigger_rssi_level=-10, trigger_rssi_change=5, active_channel_time=15,
                                                       passive_channel_time=20, enable_instant_scan=1, enable_multi_probe=0)
            # Start sniffer before association and scan
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            logger().info("Starting to join the AP")
            self.sl_collections.join_to_wifi_network_at_cmd(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                            power_save=True, ping_after_power_save=False, retry_count=3)
            logger().info("DUT successfully connected with AP")
            time.sleep(2)
            logger().info("\n *** Enable BGscan *** \n")
            self.wifi_dut.interfaces.wifi.scan(interface=5, filter_ssid="", scan_type=8, **self.bgscan_kwargs)
        except Exception as e:
            logger().info(f"\n\n **** Got exception in BG scan thread: {str(e)} ****\n\n")
            raise

@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient}
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_at_wifi_rsi_sta_connectivity_with_bgscan_2g4_c778472(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                              request, sniffer_filter, sl_collections):
    ''' This test case is to verify the background scan functionality in 2.4GHz band. '''
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"Device MAC address: {sa_addr}")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, filter_name="probe_request")

        # Stop sniffer and validate packets
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient}
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_at_wifi_rsi_sta_bgscan_channels_1_6_11_c778473(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                         request, sniffer_filter, sl_collections):
    ''' This test case is to verify the background scan functionality on channels 1, 6, and 11 in 2.4GHz band. '''
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
    channel_bitmap = get_channel_bitmap_2g4([1, 6, 11])
    logger().info(f"Device MAC address: {sa_addr}")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          bgscan_kwargs={"channel_bitmap_2g4": channel_bitmap})
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Stop sniffer and validate packets
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, filter_name="probe_request")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

