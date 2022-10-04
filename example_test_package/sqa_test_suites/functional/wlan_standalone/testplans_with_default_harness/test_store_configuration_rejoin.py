import pytest
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116StoreConfiguration, RS9116Region, RS9116RegionCode, RS9116ModuleType, \
    RS9116CustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116CertificateType, RS9116PowerSaveProcedureTypes, \
    RS9116ExtCustomFeatureBitMap
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import time
from utf.utils.logger import get_logger
# from utf.interfaces.wifi import WlanError
from utf.interfaces.cli import CLITransportException
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.wifi import WlanError
from utf.utils import mac_address_to_string
from utf.interfaces.switch import Switch
import test_store_configuration as sc

"""
    setup requirement:

        setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP -ASUS)
        5. Sniffer(NUC)
        6. PDU setup
    Author: swathi.pathuri
"""


def logger():
    return get_logger(__name__)


ping_count = 20
iter_count = 5
pdu_state = False

class FilterPacket:

    def delta_between_probe_packet(self):
        import math
        packet_filter_seq_no = '= Sequence number:'
        time_delta_from_previous_packet = "Time delta from previous captured frame"
        sniffer_dict = dict()
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if time_delta_from_previous_packet in line:
                time_delta = line.strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '').strip()
            if packet_filter_seq_no in line:
                sequence_no = line.split(':')[1].strip()
                sniffer_dict[sequence_no] = time_delta

        filter_file.close()
        logger().info(sniffer_dict)
        return sniffer_dict


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 2
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": '12214040487', "security": 'WPA2'})
def test_store_config_by_turning_off_AP_C19082(wifi_sniffer, wifi_dut, wifi_access_point, switch):

    try:
        global pdu_state

        testcase = "test_store_config_by_turning_off_AP_C19082"
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info(f'PDU state = {pdu_state}')
        if pdu_state is False:
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)

        wifi_dut.interfaces.wifi.rejoin(rejoin_max=2, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = sc.wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("Getting the ip")
        #get ip through dhcp
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Device ip : {device_ip}")

        logger().info("Enabling auto configuration")
        #below api save the AP configuration
        wifi_dut.interfaces.wifi.config_save()
        #below api enables the auto configuration
        wifi_dut.interfaces.wifi.config_enable(1, 0)

        #logger().info("Turning off AP")
        #below api is used to turn off AP
        #wifi_access_point.interfaces.wifi.stop_ap()
        # below api is used to reset the AP
        logger().info('***** Turn off Access point *****')
        if pdu_state is True:
            switch.interfaces.pdu_switch.turn_off()
            pdu_state = False

        for count in range(0, iter_count):
            logger().info("Initiating wireless de init")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(2)
            with pytest.raises(WlanError) as exc_info:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0, timeout=120)
            assert exc_info.value.error_code == 0x3, "wrong error code found"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Disable auto configuration")
        # Disable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = sc.cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e
    finally:
        if pdu_state is False:
            logger().info('\n\n Finally Turn on the AP ')
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)

# #testcase id:2.1.21.13
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 0,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "eap_cert": "wifi-user.pem",
    }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": '12214040487', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_store_config_rejoin_specific_channel_C19100(wifi_sniffer,wifi_dut,wifi_access_point,switch):

    try:

        testcase = "test_store_config_rejoin_specific_channel_C19100"
        validation = True
        packet_filter2 = False
        channel_bitmap_2_4 = 1057
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        channel_list = [1, 6, 11]
        global pdu_state
        logger().info(f'PDU state = {pdu_state}')
        if pdu_state is False:
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)

        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        logger().info("Initiating scan")
        wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                        scan_bitmap_5=channel_bitmap_5,
                                                        scan_feature=scan_feature_extend)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = sc.wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("Getting the IP")
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Device ip : {device_ip}")

        logger().info("Enabling auto configuartion")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # logger().info("Turning OFF the AP")
        # # below api is used to turn off AP
        # wifi_access_point.interfaces.wifi.stop_ap()

        logger().info('***** Turn off Access point *****')
        if pdu_state is True:
            switch.interfaces.pdu_switch.turn_off()
            pdu_state = False

        time.sleep(10)
        for channel in channel_list:

            logger().info(f"Configuring the sniffer with channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel)

            logger().info("Starting the capture")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

            packet_filter1 = f'wlan_radio.channel == {channel} and wlan.sa == {dut_mac_address} ' \
                             f'and wlan.fc.type_subtype == 0x0004 ' \
                             f'and wlan.da == ff:ff:ff:ff:ff:ff '

            logger().info("Initiating wireless de init")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(2)
            with pytest.raises(WlanError) as exc_info:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0, timeout=120)
            assert exc_info.value.error_code == 0x3, "wrong error found"

            logger().info("Stopping the capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(f"validating probe requests in  sniffer capture with filter : {packet_filter1}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)

        time.sleep(10)
        logger().info("Disabling auto configuration")
        # Disables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = sc.cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e
    finally:
        if pdu_state is False:
            logger().info('\n\n Finally Turn on the AP ')
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 0,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disable_store_config", "disassociated"])
def test_verify_rejoin_func_with_max_retry_count_C19102(wifi_sniffer, wifi_access_point, wifi_dut,switch):

    try:
        validation = True
        global pdu_state
        time_delta = 4
        packet_filter2 = 'Probe Request'
        prob_req_obj = FilterPacket()
        testcase = "test_verify_rejoin_func_with_max_retry_count_C19102"
        logger().info(f'PDU state = {pdu_state}')
        if pdu_state is False:
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)

        logger().info("========= Enabling rejoin on dut ==============")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = sc.wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("getting the ip")
        # Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f"device_ip : {device_ip}")

        logger().info("enabling auto configuration ")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()

        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        for i in range(0, 3):

            logger().info("Initiating wireless de init")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(2)
            with pytest.raises(WlanError) as exc_info:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0, timeout=120)
            if exc_info.value.error_code == 0x5A5A:
                status = True
                break
            else:
                logger().info("retrying for 3 times")
                status = False
                continue
        assert status, f"Wrong error code found"
        time.sleep(10)

        logger().info("getting the wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"{result}")
        assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

        wifi_dut.interfaces.wifi.associated = True
        logger().info("Initiating ping")
        #ping
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device before store configuration"
        logger().info("Ping successful")

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        # logger().info("==========stopping access point========")
        # wifi_access_point.interfaces.wifi.stop_ap()
        logger().info('***** Turn off Access point *****')
        if pdu_state is True:
            switch.interfaces.pdu_switch.turn_off()
            pdu_state = False
        time.sleep(10)

        # Fetches the DUT Mac Address
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT  MAC_Address: {mac_address}")

        #Validating Prob Request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff'
        time.sleep(120)
        wifi_dut.interfaces.wifi.associated = True

        logger().info("stopping the capture")
        #Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating broadcast probe requests")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)['packet_count'],\
        "Unable to find the brodcast probe requests"

        probe_packets_dict = prob_req_obj.delta_between_probe_packet()
        logger().info(f'probe request packet time delta list = {probe_packets_dict}')

        seq_num_list = list(probe_packets_dict.keys())
        probe_packets_time_delta_list = list(probe_packets_dict.values())
        probe_packets_time_delta_list.pop(0)
        logger().info(f"len of probe_packets_time_delta_list :{len(probe_packets_time_delta_list)}")

        logger().info(f"seq numbers list:{seq_num_list}")
        logger().info(f"time diff between probe request list:{probe_packets_time_delta_list}")

        diff_seq_list = [int(seq_num_list[i+1])-int(seq_num_list[i]) for i in range(len(seq_num_list)-1)]

        logger().info(f"diff between seq numbers :{diff_seq_list}")

        logger().info(f"len of diff_seq_list {len(diff_seq_list)}")

        for i in range(0, len(diff_seq_list)):
            time_diff = probe_packets_time_delta_list[i]
            logger().info(f"time diff between packets {int(float(time_diff))}")
            logger().info(f"diff between seq numbers {diff_seq_list[i]}")
            logger().info(f"min : {int(time_delta) * diff_seq_list[i]} and max : "
                          f"{((int(time_delta)+0.2) * (diff_seq_list[i]))}")

            is_between =int(float(time_diff)) in range(int((int(time_delta) * diff_seq_list[i])-1),
                                                        int((int(time_delta)+0.2) * diff_seq_list[i])+1)
            if is_between is False:
                logger().info(is_between)
                status = is_between
                break
            else:
                logger().info(is_between)
                status = is_between
        assert status is True, f'Expected Valid Probe Request packet time delay is {status}'

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()

        logger().info("Disabling auto configuration")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = sc.cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e
    finally:
        if pdu_state is False:
            logger().info('\n\n Finally Turn on the AP ')
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "channel": 1, "passphrase": '12214040487', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disable_store_config", "disassociated"])
def test_verify_rejoin_func_with_max_retry_50_C19087(wifi_sniffer, wifi_access_point, wifi_dut, switch):

    try:
        validation = True
        time_delta = 1
        packet_filter2 = 'Probe Request'
        prob_req_obj = FilterPacket()
        global pdu_state
        testcase = "test_verify_rejoin_func_with_max_retry_50_C19087"
        logger().info(f'PDU state = {pdu_state}')
        if pdu_state is False:
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)

        logger().info("========= Enabling rejoin on dut ==============")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=50, scan_interval=1, beacon_missedcount=40, first_time_retry=1)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = sc.wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("getting the ip")
        # Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f"device_ip : {device_ip}")

        # Fetches the DUT Mac Address
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT  MAC_Address: {mac_address}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("enabling auto configuration ")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()

        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        time.sleep(2)

        for i in range(0, 3):

            logger().info("Initiating wireless de init")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(2)
            with pytest.raises(WlanError) as exc_info:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0, timeout=120)
            if exc_info.value.error_code == 0x5A5A:
                status = True
                break
            else:
                logger().info("retrying for 3 times")
                status = False
                continue
        assert status, f"Wrong error code found"
        time.sleep(10)

        logger().info("getting the wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"{result}")
        assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

        logger().info("==========stopping access point========")
        #wifi_access_point.interfaces.wifi.stop_ap()
        if pdu_state is True:
            switch.interfaces.pdu_switch.turn_off()
            pdu_state = False
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(150)
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating beacons
        packet_filter2 = f'wlan.fc.type_subtype == 0x0008 and wlan.addr == {bssid}'
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            "beacons found even AP is turned OFF"

        for i in range(0, iter_count):

            logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_probe_req")

            logger().info("Initiating wireless de init")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(2)
            with pytest.raises(WlanError) as exc_info:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0, timeout=120)
            assert (exc_info.value.error_code == 0x3 or exc_info.value.error_code == 0x19),\
                "Wrong error code found"
            time.sleep(150)
            logger().info("stopping the capture")
            #Stop Sniffer
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating Prob Request
            packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff'

            logger().info("Validating broadcast probe requests")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1,packet_filter2)[
                'packet_count'], \
                "Unable to find the brodcast probe requests"

            probe_packets_dict = prob_req_obj.delta_between_probe_packet()

            seq_num_list = list(probe_packets_dict.keys())

            logger().info(f'probe request packet sequence numbers list = {seq_num_list}')

            packet_count = len(seq_num_list)

            logger().info(f"packet_count: {packet_count}")

            diff_bw_seq_num = [int(seq_num_list[i + 1]) - int(seq_num_list[i]) for i in range(len(seq_num_list) - 1)]
            for diff in diff_bw_seq_num:
                if int(diff) == 1:
                    logger().info("difference between probe req  seq numbers is 1")
                    continue
                else:
                    packet_count = packet_count + int(diff-1)
                    logger().info(f"difference between probe req  seq numbers is {diff}")
            assert packet_count == 50,\
            f"Unable to find the brodcast probe requests count {packet_count}"

            logger().info(f"packet_count : {packet_count}")

        logger().info("Disabling auto configuration")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = sc.cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e
    finally:
        if pdu_state is False:
            logger().info('\n\n Finally Turn on the AP ')
            switch.interfaces.pdu_switch.turn_on()
            pdu_state = True
            time.sleep(60)

