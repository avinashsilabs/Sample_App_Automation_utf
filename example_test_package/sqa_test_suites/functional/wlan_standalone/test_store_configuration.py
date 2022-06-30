import pytest
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116StoreConfiguration, RS9116Region, RS9116RegionCode, RS9116ModuleType, \
    RS9116CustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
import time
from utf.utils.logger import get_logger
# from utf.interfaces.wifi import WlanError
from utf.interfaces.cli import CLITransportException
from utf.utils.iperf.iperf_utils import print_dict


"""
    setup requirement:

        setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP -ASUS)
        5. Sniffer(NUC)
        
    Author: swathi.pathuri
"""
def logger():
    return get_logger(__name__)

ping_count = 10
iter_count = 5

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

# this thread used for wifi join
class Wifi_data_tx():
    def __init__(self, wifi_dut=None, \
                 wifi_access_point=None, \
                 wifi_client=None,\
                 net_perf_client=None, protocol=None, device_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip


    def __print_throughput(self,iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_traffic(self):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        logger().info("starting the server from Remote device")

        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.device_ip,
                                                             protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()

        logger().info("sending data from DUT")
        # open socket and send traffic
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            self.device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        time.sleep(5)
        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        self.__print_throughput(tp)
        logger().info("data transfer is successful")
        time.sleep(5)

class cleanup_store_config():
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def dut_recovery(self):
        tries = 0
        while tries < 3:
            tries += 1
            try:
                logger().info("Initiating reset for device cleanup")
                self.wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.associated = True
                logger().info("Initializing the DUT")
                self.wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9, retries=1)
                time.sleep(10)
                return True
            except:
                logger().info("clean up process failed ,retrying for 3 times")
                # if tries==2:
                #     return


    def disconnect(self):

        try:
            logger().info("Initiating disconnect for cleanup")
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(5)
            logger().info("cfg disable")
            # Enables the store configuration
            self.wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
            return True
        except:
            logger().info("clean up process failed")



class wifi_join():

    def __init__(self, wifi_dut,wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def join_to_ap(self):
        for i in range(0,2):
            try:
                self.wifi_dut.interfaces.wifi.associated = False
                logger().info("joining to the AP")
                # DUT connects to AP after join_ap API is executed
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
                return True
            except Exception as e:
                if "Error code: 0x2" in str(e):
                    logger().info("Initiating disconnect for cleanup")
                    self.wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
                    time.sleep(5)
                    logger().info("cfg disable")
                    # Enables the store configuration
                    self.wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
                    if i ==2:
                        raise

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        #"first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut",
                      wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])

def test_store_config_open_C19081(wifi_sniffer, wifi_access_point, wifi_dut):

    try:
        testcase = "test_store_config_open_C19081"
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("Getting the IP")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Found device ip : {device_ip}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device before store configuration"

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        for i in range(0,iter_count):

            logger().info("Initiating wireless de init")
            #deinit
            logger().info("Instead of reset need to add  wireless de init")
            wifi_dut.interfaces.wifi.reset_soft()
            wifi_dut.interfaces.wifi.associated = True
            time.sleep(2)
            logger().info("Initiating wireless init")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            time.sleep(20)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device after store configuration"
            time.sleep(5)
            logger().info("Ping successful")

            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()
        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'],\
            'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 1
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": 'STORE_CONFIG_TEST', "security": 'WPA2',
                          "channel": 36})
def test_store_config_band_5_WPA2_C19085(wifi_sniffer, wifi_access_point, wifi_dut):

    try:
        testcase = "test_store_config_band_5_WPA2_C19085"

        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        for i in range(0, iter_count):

            logger().info("Initiating reset instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            time.sleep(20)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result,"AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device after store configuration"
            logger().info("ping is successful")

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()

            time.sleep(5)

        logger().info("Disabling auto configuration")
        # Disables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point1", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "security": 'WPA2', "passphrase": '123412341234'})
def test_store_config_region_US_EU_JP_C19088(wifi_sniffer, wifi_access_point, wifi_dut):

    try:
        region_list = ['US', "Europe", "Japan"]
        for region in region_list:

            testcase = f"test_store_config_region_US_EU_JP_C19088_{region}"

            logger().info("reset the DUT")
            wifi_dut.interfaces.wifi.reset_soft()

            logger().info("Initializing the DUT")
            logger().info(f"setting the region to {region}")

            if region == "US":
                # Set the region to US in DUT
                wifi_dut.interfaces.wifi.init(region=RS9116Region.FromUser,
                                              region_code=RS9116RegionCode.US,
                                              module_type=RS9116ModuleType.WithOnboardAntenna)
                channel = 11
                logger().info(f"configuring access point with channel {channel} and region : {region}")
                # Configures the Access point with the channel selected
                wifi_access_point.interfaces.wifi.start_ap(channel=channel, region=region)

            if region == "Europe":
                # Set the region to US in DUT
                wifi_dut.interfaces.wifi.init(region=RS9116Region.FromUser,
                                              region_code=RS9116RegionCode.Europe,
                                              module_type=RS9116ModuleType.WithOnboardAntenna)

                channel = 12
                logger().info(f"configuring access point with channel {channel} and region : {region}")
                # Configures the Access point with the channel selected
                wifi_access_point.interfaces.wifi.start_ap(channel=channel, region=region)
            if region == "Japan":
                # Set the region to US in DUT
                wifi_dut.interfaces.wifi.init(region=RS9116Region.FromUser,
                                              region_code=RS9116RegionCode.Japan,
                                              module_type=RS9116ModuleType.WithOnboardAntenna)

                channel = 1
                logger().info("Japan region not supported by the AP")
                #continue

                logger().info(f"configuring access point with channel {channel} and region : US")
                # Configures the Access point with the channel selected
                wifi_access_point.interfaces.wifi.start_ap(channel=channel, region="US")

            validation = True
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

            logger().info("joining to the AP")
            # DUT connects to AP after join_ap API is executed
            join_obj = wifi_join(wifi_dut, wifi_access_point)
            assert join_obj.join_to_ap(), "Join failed"

            logger().info("Getting the IP")
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            wifi_dut.interfaces.wifi.start_ip()

            # The below api parses DUTs IP address
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"Found the device ip : {device_ip}")

            logger().info("Getting the DUT mac")
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")

            bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP MAC: {bssid}")

            logger().info("Enable Auto Configuration")
            # Save the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_save()
            logger().info("Getting cfg get response")
            result = wifi_dut.interfaces.wifi.cfg_get()
            logger().info(f"cfg get command response {result}")
            if region == "US":
                assert "region_code:1" in str(result), "Region US not found in cfg get response"
            if region == "Europe":
                assert "region_code:2" in str(result), "Region Europe not found in cfg get response"
            if region == "Japan":
                assert "region_code:3" in str(result), "Region Japan not found in cfg get response"

            logger().info(f"Region {region} found in cfg_get response")

            # Enable the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

            for i in range(0,iter_count):

                logger().info("Instead of deinit ,resetting the device")
                wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(2)

                wifi_dut.interfaces.wifi.associated = True
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
                time.sleep(10)

                logger().info("getting wireless info")
                result = wifi_dut.interfaces.wifi.get_wireless_info()
                assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

                logger().info("Initiating power save")
                # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
                # DUT to power save in Wifi+bluetooth mode
                wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
                wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

                logger().info("Initiating ping")
                # Ping to dut from third party device
                status = ping(device_ip, ping_count)
                assert status == True, f"DUT is not responding to ping request from third party device after store " \
                                    f"configuration when running test  with channel {channel} in region {region}"
                time.sleep(5)

                wifi_dut.interfaces.wifi.associated = True

                logger().info("Initiating disconnect from DUT")
                wifi_dut.interfaces.wifi.leave()

            logger().info("Disable auto configuration")
            # Disable the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating the power management bit
            packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                             f'and wlan.sa == {dut_mac_address}'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'],\
                'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as e:
            logger().info(f"Exception: {str(e)}")
            clean_up = cleanup_store_config(wifi_dut)
            if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
                clean_up.dut_recovery()
            clean_up.disconnect()
            raise e




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
def test_store_config_band_dual_C19090(wifi_sniffer, wifi_dut, wifi_access_point):

    try:

        dut_connected_to_ap = 0
        channel_list = [1, 36]
        for channel in channel_list:

            testcase = f"test_store_config_band_dual_C19090_{channel}"

            logger().info(f"Configuring the AP with channel : {channel}")
            # Configures the Access point with the channel selected
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)

            validation = True
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

            bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP MAC: {bssid}")

            if dut_connected_to_ap == 0:

                logger().info(f"joining to the AP")
                # DUT connects to AP after join_ap API is executed
                # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                wifi_dut.interfaces.wifi.join(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                              security=wifi_access_point.interfaces.wifi.security,
                                              passphrase=wifi_access_point.interfaces.wifi.passphrase)

                logger().info("Getting the ip")
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                wifi_dut.interfaces.wifi.start_ip()
                # The below api parses DUTs IP address
                device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                logger().info(f"Device ip : {device_ip}")

                logger().info("Getting the DUT mac")
                dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"DUT MAC_Address: {dut_mac_address}")

                dut_connected_to_ap = 1

                logger().info("saving the configuration")
                # Save the wireless configuration in the flash
                wifi_dut.interfaces.wifi.config_save()

                logger().info("Getting cfg get response")
                result = wifi_dut.interfaces.wifi.cfg_get()
                logger().info(f"cfg get command response {result}")
                assert "band:2" in str(result),"dual band not found in cfg get response"
                logger().info("dual band found in cfg get response")

                logger().info("Enabling auto configuration")
                # Enable the wireless configuration in the flash
                wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

            for i in range(0,iter_count):

                logger().info("Initiating reset instead of deinit")
                wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(2)

                wifi_dut.interfaces.wifi.associated = True
                logger().info("Initializing DUT")
                wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
                time.sleep(10)
                logger().info("getting wireless info")
                result = wifi_dut.interfaces.wifi.get_wireless_info()

                assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

                logger().info("Initiating Power save")
                # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
                # DUT to power save in Wifi+bluetooth mode
                wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
                wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

                logger().info("Initiating Ping")
                # Ping to dut from third party device
                status = ping(device_ip, ping_count)
                assert status == True, f"DUT is not responding to ping request from third party device after store " \
                                    f"configuration when running test  with channel {channel}"

                logger().info("Ping successful")
                wifi_dut.interfaces.wifi.associated =True
                logger().info("Initiating disconnect from DUT")
                wifi_dut.interfaces.wifi.leave()
                logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            # Validating the power management bit
            packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                             f'and wlan.sa == {dut_mac_address}'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 1'
            #wifi_dut.interfaces.wifi.inited = True

            logger().info(f"Disabling the radio of AP")
            # Configures the Access point with the channel selected
            wifi_access_point.interfaces.wifi.stop_ap()

        logger().info("Disable auto configuration")
        # Disable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e






@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
def test_store_config_by_turning_off_AP_C19082(wifi_sniffer, wifi_dut, wifi_access_point):

    try:

        testcase = "test_store_config_by_turning_off_AP_C19082"
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
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

        logger().info("Turning off AP")
        #below api is used to turn off AP
        wifi_access_point.interfaces.wifi.stop_ap()
        # below api is used to reset the AP

        for i in range(0,iter_count):

            logger().info("resetting the dut instead of deinit")
            #de_init
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)
            with pytest.raises(CLITransportException) as ex:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9, retries=0)
                assert "Error Code : 0x3" in str(ex), "Wrong error code found"

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Disable auto configuration")
        # Disable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e

# #testcase id:2.1.21.13
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
def test_store_config_rejoin_specific_channel_C19100(wifi_sniffer,wifi_dut,wifi_access_point):

    try:

        testcase = "test_store_config_rejoin_specific_channel_C19100"
        validation = True
        packet_filter2 = False
        channel_bitmap_2_4 = 1057
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        channel_list = [1, 6, 11]

        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        logger().info("Initiating scan")
        wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                        scan_bitmap_5=channel_bitmap_5,
                                                        scan_feature=scan_feature_extend)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
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

        logger().info("Turning OFF the AP")
        # below api is used to turn off AP
        wifi_access_point.interfaces.wifi.stop_ap()

        time.sleep(10)
        for channel in channel_list:

            logger().info(f"Configuring the sniffer with channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel)

            logger().info("Starting the capture")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

            packet_filter1 = f'wlan_radio.channel == {channel} and wlan.sa == {dut_mac_address} ' \
                             f'and wlan.fc.type_subtype == 0x0004 ' \
                             f'and wlan.da == ff:ff:ff:ff:ff:ff '

            logger().info("Resetting the DUT instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            with pytest.raises(CLITransportException) as ex:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9, retries=0)
                assert "Error Code : 0x3" in str(ex), "wrong error code found"

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
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": '12214040487', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_Config_LP_Power_Save_C19089(wifi_dut,wifi_access_point,wifi_sniffer):

    try:
        validation = True
        testcase = "test_Store_Config_LP_Power_Save_C19089"

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info("Starting the capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        # DUT connects to AP after join_ap API is executed
        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        # Fetches the DUT MAC Address
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Actual MAC_Address: {mac_address}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        # Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Device ip : {device_ip}")

        logger().info("Initiating power save")
        # Enables the power Save in wifi mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1)
        # Enables the power Save in BT mode
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode1)

        logger().info("Enabling auto configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()

        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        time.sleep(10)
        # resetting the dut
        for count in range(0,iter_count):
            logger().info("resetting the DUT instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)
            wifi_dut.interfaces.wifi.associated = True
            logger().info("=========Wireless Init============")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            time.sleep(10)

            logger().info("getting the wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            logger().info(f"{result}")
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating ping")
            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device before store configuration"
            logger().info("ping is successful")

            logger().info("Getting cfg get response")
            result = wifi_dut.interfaces.wifi.cfg_get()
            logger().info(f"cfg get command response {result}")
            logger().info("validating power mode settings in cfg get response")
            assert (("powermode:1" in str(result)) and ("ulp_mode:1" in str(result))),"Expected power mode not found in cfg get response"
            logger().info("powermode:1  and ulp_mode:1 found in cfg get response")
            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {mac_address}'
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'
        # Disable store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
def test_verify_rejoin_func_with_max_retry_count_C19102(wifi_sniffer, wifi_access_point, wifi_dut):

    try:
        validation = True
        time_delta = 4
        packet_filter2 = 'Probe Request'
        prob_req_obj = FilterPacket()
        testcase = "test_verify_rejoin_func_with_max_retry_count_C19102"

        logger().info("========= Enabling rejoin on dut ==============")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
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
        time.sleep(10)

        logger().info("Resetting DUT instead of deinit")
        # resetting the dut
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(2)

        logger().info("Initializing the DUT")
        wifi_dut.interfaces.wifi.associated = True

        # Wireless Init
        wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)

        logger().info("getting the wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"{result}")
        assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

        wifi_dut.interfaces.wifi.associated = True
        logger().info("Initiating ping")
        #ping
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device before store configuration"
        logger().info("Ping successful")

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("==========stopping access point========")
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(10)

        # Fetches the DUT Mac Address
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT  MAC_Address: {mac_address}")

        #Validating Prob Request
        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff'
        time.sleep(120)
        wifi_dut.interfaces.wifi.associated = False

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
            logger().info(f"time diff between packets {float(time_diff)}")
            logger().info(f"diff between seq numbers {diff_seq_list[i]}")
            is_between = int(float(time_diff)) in range((time_delta * diff_seq_list[i]),((time_delta * diff_seq_list[i]) + 1))
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
        wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)

        logger().info("Disabling auto configuration")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "channel": 1, "passphrase": '12214040487', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disable_store_config", "disassociated"])
def test_verify_rejoin_func_with_max_retry_50_C19087(wifi_sniffer, wifi_access_point, wifi_dut):

    try:
        validation = True
        time_delta = 1
        packet_filter2 = 'Probe Request'
        prob_req_obj = FilterPacket()
        testcase = "test_verify_rejoin_func_with_max_retry_50_C19087"

        logger().info("========= Enabling rejoin on dut ==============")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=50, scan_interval=1, beacon_missedcount=40, first_time_retry=1)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
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

        logger().info("Resetting DUT instead of deinit")
        # resetting the dut
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(2)
        logger().info("Initializing the DUT")
        wifi_dut.interfaces.wifi.associated = True

        # Wireless Init
        wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)

        logger().info("getting the wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"{result}")
        assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

        logger().info("==========stopping access point========")
        wifi_access_point.interfaces.wifi.stop_ap()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(100)
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating beacons
        packet_filter2 = f'wlan.fc.type_subtype == 0x0008 and wlan.addr == {bssid}'

        logger().info(
            f"beacons : {wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            "beacons found even AP is turned OFF"

        for i in range(0, iter_count):

            logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_probe_req")

            logger().info("Resetting DUT instead of de init")
            # resetting the dut
            wifi_dut.interfaces.wifi.reset_soft()
            #time.sleep(2)
            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.associated = False

            with pytest.raises(CLITransportException) as ex:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9, retries=0)
                assert ("Error Code : 0x3" or "Error Code : 0x19") in str(ex), "Wrong error code found"
            time.sleep(150)
            logger().info("stopping the capture")
            #Stop Sniffer
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating Prob Request
            packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff'

            logger().info(f"Validating broadcast probe requests : {wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['find_packet_num']}")

            logger().info("Validating broadcast probe requests")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
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
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": 'STORE_CONFIG_TEST', "security": 'WPA2'})
def test_store_config_without_powersave_C19103(wifi_sniffer, wifi_access_point, wifi_dut):

    try:
        testcase = "test_store_config_without_powersave_C19103"

        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(),"Join failed"

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")

        logger().info("Initiating power save")
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        logger().info("Initiating reset instead of deinit")
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(2)

        wifi_dut.interfaces.wifi.associated = True
        logger().info("Initializing the DUT")
        wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
        time.sleep(20)

        logger().info("getting wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        assert wifi_access_point.interfaces.wifi.ssid in result,"AP ssid not found in the get wireless info"

        logger().info("Initiating ping")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device after store configuration"
        logger().info("ping is successful")

        wifi_dut.interfaces.wifi.associated = True
        logger().info("Initiating disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Disabling auto configuration")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        time.sleep(5)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        logger().info(f"validating power save in sniffer with filter {packet_filter1}")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'],\
            'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": 'STORE_CONFIG_TEST', "security": 'WPA2'})
def test_store_config_aggregation_C19101(wifi_sniffer, wifi_access_point, wifi_dut):

    try:
        testcase = "test_store_config_aggregation_C19101"

        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(),"Join failed"

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)


        for i in range(0,iter_count):
            logger().info("Initiating reset instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            time.sleep(20)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result,"AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping_qos(device_ip, ping_count, qos_category="0xE0")
            assert status == True, "DUT is not responding to ping request from third party device after store configuration"
            logger().info("ping is successful")

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()

            time.sleep(5)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating the action frames
            packet_filter1 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.sa =={bssid}) ' \
                             f'&& (wlan.da == {dut_mac_address})'

            # Validating the action frames
            packet_filter2 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.da == {bssid}) ' \
                             f'&& (wlan.sa == {dut_mac_address})'

            # Validating the action frames
            packet_filter3 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.da =={bssid}) ' \
                             f'&& (wlan.sa == {dut_mac_address})'

            # Validating the action frames
            packet_filter4 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.sa == {bssid}) ' \
                             f'&& (wlan.da == {dut_mac_address})'

            logger().info(f"validating action frames in sniffer with filter: {packet_filter1}" \
                          f"filter2 : {packet_filter2}" \
                          f"filter3 : {packet_filter3}"
                          f"filter3 : {packet_filter4}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1), f'packets not found in sniffer with filter:{packet_filter1}'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter2), f'packets not found in sniffer with filter:{packet_filter2}'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter3), f'packets not found in sniffer with filter:{packet_filter3}'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter4), f'packets not found in sniffer with filter:{packet_filter4}'

            # Validating the action frames
            packet_filter5 = f'(wlan.addr =={dut_mac_address} && (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x0019))'

            logger().info(f"validating data and block ack in sniffer with filter: {packet_filter5}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter5), f'packets not found in sniffer with filter:{packet_filter5}'

        logger().info("Disabling auto configuration")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e


@pytest.mark.skip
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity ,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        # Note that SSL cert bypass is required to avoid SSL handshake error.
        # It is unclear if this is a bug in the AWS SAPI network wrapper
        # or in the 9116 firmware
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.SSLCertBypass | RS9116ExtTCPIPFeatureBitMap.Default,
        },
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])

def test_store_config_AWS_conn_listen_inter_C19105(wifi_sniffer, wifi_dut, wifi_access_point):

    try:

        validation = True
        testcase = "test_store_config_AWS_conn_listen_inter_C19105"
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(),"Join failed"

        logger().info("getting the IP")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device_ip : {device_ip}")

        logger().info(f"Initiating ping from remote device")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device before store configuration"
        logger().info("Ping successful")

        logger().info("enabling auto configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        for count in range(1, 6):
            logger().info("reset the DUT ,instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.associated = True
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            time.sleep(10)

            logger().info("Ping to the DUT")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device after store configuration"
            logger().info("Ping successful")

            # # Disable power save in the DUT
            # wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
            # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled)

            logger().info("Initiating power save")
            # Enable listen interval based power save in the DUT
            wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                                listen_interval=1000 + (count * 100))
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            topic_1 = "sdk/test/Python"
            message = '{"message": "my payload"}'

            logger().info("Initiating aws connection")
            wifi_dut.interfaces.wifi.aws_iot_connect()
            time.sleep(2)
            logger().info("Initiating aws subscription")
            wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)
            logger().info("Initiating aws publish")
            wifi_dut.interfaces.wifi.aws_iot_publish(
                topic_1, message, 0
                )
            time.sleep(10)
            logger().info("Getting the list of async events")
            events = wifi_dut.interfaces.wifi.get_async_events()

            if len(events):
                for event in events:
                    assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
                    assert message == event.event_data.payload, "sent and received messages are not matching"
            logger().info("Unsubscribe")
            wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
            logger().info("Disconnect")
            wifi_dut.interfaces.wifi.aws_iot_disconnect()
            time.sleep(1)

            wifi_dut.interfaces.wifi.associated = True

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()

            logger().info("Disabling auto configuration")

            # Enables the store configuration
            wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

            logger().info("stopping the capture")
            # Stop Sniffer
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating the power management bit
            packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                             f'and wlan.sa == {dut_mac_address}'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as e:
            logger().info(f"Exception: {str(e)}")
            clean_up = cleanup_store_config(wifi_dut)
            if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
                clean_up.dut_recovery()
            clean_up.disconnect()
            raise e



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer,
        "rejoin_max_retry": 0,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": '123123123'})
def test_wireless_config_WPA2_C19093(wifi_sniffer, wifi_access_point,wifi_client, wifi_dut, wiseconnect_web, net_perf_client, protocol):

    try:
        testcase = "test_wireless_config_WPA2_C19093"

        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(),"Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device after store configuration"
        logger().info("ping is successful")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        # configures the values from harness on given ip address of web page
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip,\
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid,\
                                                                   security=wifi_access_point.interfaces.wifi.security,\
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )

        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert wifi_access_point.interfaces.wifi.ssid in str(result), "ssid not found in cfg get response"
        logger().info("ssid found in cfg get response")

        for i in range(0, iter_count):

            logger().info("Initiating reset instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result,"AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device after store configuration"
            logger().info("ping is successful")

            iperf_tx = Wifi_data_tx(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, device_ip)
            iperf_tx.run_traffic()

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

        logger().info("cfg disable")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 1
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"channel": 36})
def test_wireless_config_5GHZ_C19097(wifi_sniffer, wifi_access_point,wifi_client, wifi_dut, wiseconnect_web):

    try:

        testcase = "test_wireless_config_5GHZ_C19097"

        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(),"Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")

        ping_count = 60
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device after store configuration"
        logger().info("ping is successful")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")


        logger().info("Enable wireless Configuration")
        # Save the wireless configuration in the flash
        # configures the values from harness on given ip address of web page
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip, band="5.0",\
                                                                   channel=wifi_access_point.interfaces.wifi.channel,\
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid,\
                                                                   security=wifi_access_point.interfaces.wifi.security, \
                                                                   cipher="AES",\
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )

        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert ((wifi_access_point.interfaces.wifi.ssid in str(result)) and ("band:1" in str(result)) \
               and (f"scan_cnum:{wifi_access_point.interfaces.wifi.channel}" in str(result))), \
            "expected ssid,band,channel not found in cfg get response"
        for i in range(0, iter_count):

            logger().info("Initiating reset instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            #time.sleep(20)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device after store configuration"
            logger().info("ping is successful")

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()

            time.sleep(5)

        logger().info("cfg disable")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        logger().info(f"validating power save in sniffer with filter {packet_filter1}")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": '123123123'})
def test_wireless_config_Dual_1_C19095(wifi_sniffer, wifi_access_point,wifi_client, wifi_dut, wiseconnect_web, net_perf_client, protocol):

    try:
        testcase = "test_wireless_config_Dual_1_C19095"

        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(),"Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device after store configuration"
        logger().info("ping is successful")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        # configures the values from harness on given ip address of web page
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip,band="Dual", \
                                                                   channel=wifi_access_point.interfaces.wifi.channel,
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid,\
                                                                   security=wifi_access_point.interfaces.wifi.security,\
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )

        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert (wifi_access_point.interfaces.wifi.ssid in str(result)) and ("band:2" in str(result)) \
               and (f"scan_cnum:{wifi_access_point.interfaces.wifi.channel}" in str(result)),\
            "expected ssid,band,channel not found in cfg get response"

        for i in range(0, iter_count):

            logger().info("Initiating reset instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            #time.sleep(20)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device after store configuration"
            logger().info("ping is successful")

            iperf_tx = Wifi_data_tx(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, device_ip)
            iperf_tx.run_traffic()

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

        logger().info("cfg disable")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"channel": 36, "security": 'WPA2', "passphrase": '123123123'})
def test_wireless_config_Dual_2_C19096(wifi_sniffer, wifi_access_point,wifi_client, wifi_dut, wiseconnect_web, net_perf_client, protocol):

    try:
        testcase = "test_wireless_config_Dual_2_C19096"
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(),"Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")
        # Ping to dut from third party device

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        # configures the values from harness on given ip address of web page
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip,band="Dual", \
                                                                   channel=wifi_access_point.interfaces.wifi.channel,
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid,\
                                                                   security=wifi_access_point.interfaces.wifi.security,\
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )
        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert (f"join_ssid:{wifi_access_point.interfaces.wifi.ssid}" in str(result)) and \
               (f"band:2" in str(result)) and (f"scan_cnum:{wifi_access_point.interfaces.wifi.channel}" in str(result)),\
            "expected ssid,band,channel not found in cfg get response"
        logger().info("ssid ,band ,channel found in cfg get response")
        for i in range(0, iter_count):

            logger().info("Initiating reset instead of deinit")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)

            wifi_dut.interfaces.wifi.associated = True
            logger().info("Initializing the DUT")
            wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9)
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            iperf_tx = Wifi_data_tx(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, device_ip)
            iperf_tx.run_traffic()

            wifi_dut.interfaces.wifi.associated = True

            wifi_dut.interfaces.wifi.wlan_get_status()
            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

        logger().info("cfg disable")
        # Enables the store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise e
