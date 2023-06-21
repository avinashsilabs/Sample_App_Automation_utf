import re
import time
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf import UtfDatabaseProperties
# from test_wlan_rejoin_2g_sdk import SocketDataTransfer
from test_wlan_rejoin_2G_sdk import SocketDataTransfer
from utf_wiseconnect.interfaces.cli.rs_at_commands import RSATCommands
# from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
)

'''
wifi_dut.interfaces.wifi.scan_selective_channel() - https://jira.silabs.com/browse/WIFI_BT_UTFHELP-2473

sl_wifi_set_advanced_scan_configuration() - Instant scan parameter missing - https://jira.silabs.com/browse/WIFI_BT_UTFHELP-2475
'''



def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Enable Background scan
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Expectation of this test case is to verify different parameters of Background scan functionalities. 
        8. Validate Probe response & HT information, BG scan on primary, non US & DFS channel etc. via sniffer with
           different mode/channels 

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Vivek Verma
"""


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_bgscan_C19035(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    end_time = utf_constants.get("time_duration")
    data = 'Thisisfromclient'
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, end_time=end_time,
                                    data=data)
    '''Verify RSI_STA connectivity by enabling BG scan in 2.4Ghz band'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15, adv_passive_channel_time=20)
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

    socket_obj.wifi_join(ping_count, scan=False)

    dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"\n\nDUT MAC_Address: {dut_mac_address}")

    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        filter_name="probe_request")

    socket_obj.socket_data_transfer()
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    socket_obj.wifi_join(ping_count)
    socket_obj.socket_data_transfer()
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 2,
    },
)
@pytest.mark.wifi_dualband
def test_bgscan_dual_mode_C19036(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    end_time = utf_constants.get("time_duration")
    data = 'Thisisfromclient'
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, end_time=end_time,
                                    data=data)

    '''Verify RSI_STA connectivity by enabling BG scan in Dual band'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15, adv_passive_channel_time=20)
    # wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

    socket_obj.wifi_join(ping_count, scan=False)

    dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"\n\nDUT MAC_Address: {dut_mac_address}")

    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        filter_name="probe_request")

    socket_obj.socket_data_transfer()
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    socket_obj.wifi_join()
    socket_obj.socket_data_transfer()
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_instant_bgscan_C19037(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    end_time = utf_constants.get("time_duration")
    data = 'Thisisfromclient'
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, end_time=end_time,
                                    data=data)

    '''Verify RSI_STA connectivity by enabling instant BG scan'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15, adv_passive_channel_time=20)
    # wifi_dut.interfaces.wifi.set_bgscan(1, 1, 10, 4, 10, 15, 20, 0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

    socket_obj.wifi_join(ping_count, scan=False)

    dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"\n\nDUT MAC_Address: {dut_mac_address}")

    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        filter_name="probe_request")

    socket_obj.socket_data_transfer()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    socket_obj.wifi_join()
    socket_obj.socket_data_transfer()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_bgscan_rejoin_infinite_retry_C19038(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    end_time = utf_constants.get("time_duration")
    data = 'Thisisfromclient'
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, end_time=end_time,
                                    data=data)

    '''Re-join with infinite retry when bgscan enable. Module should rejoin. If not module should attempt infinitely.
       If it successfully rejoin to AP bgscan should happen. '''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15, adv_passive_channel_time=20)
    # wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)

    # Rejoin
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                             beacon_missed_count=40, first_time_retry_enable=0)
    wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
    socket_obj.wifi_join(ping_count, scan=False)

    dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"\n\nDUT MAC_Address: {dut_mac_address}")

    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        filter_name="probe_request")

    socket_obj.socket_data_transfer()
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(10)
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(60)

    socket_obj.socket_data_transfer()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    wifi_dut.interfaces.wifi.leave()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_bgscan_primary_channel_2G_C19039(wifi_sniffer, wifi_access_point, wifi_dut, rs_helper, utf_constants):
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    end_time = utf_constants.get("time_duration")
    data = 'Thisisfromclient'
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, end_time=end_time,
                                    data=data)
    channel_bitmap_2_4 = 0
    channel_bitmap_5 = 0
    scan_feature_extend = 0

    '''configure the channels 1,6,11 in channel_bitmap field and verify whether the BG scan is happening in those 
       particular channels only or not'''
    channel_list = [1, 6, 11]
    for channel in channel_list:
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        time.sleep(20)
        logger().info(f"Channel = {channel}")
        channel_bitmap_2_4 += 1 << (channel - 1)
        logger().info(f"channel bitmap = {channel_bitmap_2_4}")
        wifi_sniffer.interfaces.capture.configure_interface(channel)
        time.sleep(5)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        # wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                 adv_passive_channel_time=20)

        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                        scan_bitmap_5=channel_bitmap_5,
                                                        scan_feature=scan_feature_extend)

        socket_obj.wifi_join(ping_count, scan=False)

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"\n\nDUT MAC_Address: {dut_mac_address}")

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="probe_request")
        socket_obj.socket_data_transfer()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'
