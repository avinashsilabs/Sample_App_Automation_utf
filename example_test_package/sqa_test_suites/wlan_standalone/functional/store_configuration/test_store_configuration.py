import pytest
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116StoreConfiguration, RS9116Region, RS9116RegionCode, RS9116ModuleType, \
    RS9116CustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116CertificateType, RS9116PowerSaveProcedureTypes, \
    RS9116ExtCustomFeatureBitMap, RS9116JoinFeatureBitMap
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import time
from utf.utils.logger import get_logger
# from utf.interfaces.wifi import WlanError
from utf.interfaces.cli import CLITransportException
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.wifi import WlanError
from utf.utils import mac_address_to_string

"""
    setup requirement:

        setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP -ASUS)
        5. Sniffer(NUC)
        6. Radius server installed in NUC
        
    Author: swathi.pathuri
"""


def logger():
    return get_logger(__name__)


ping_count = 20
iter_count = 5


# this thread used for wifi join
class Wifi_data_tx():
    def __init__(self, wifi_dut=None, \
                 wifi_access_point=None, \
                 wifi_client=None, \
                 net_perf_client=None, protocol=None, device_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip

    def __print_throughput(self, iperf_throughput: dict):
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


class wifi_join:
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def join_to_ap(self):
        for i in range(0, 3):
            try:
                self.wifi_dut.interfaces.wifi.associated = False
                logger().info("joining to the AP")
                # DUT connects to AP after join_ap API is executed
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, timeout=40)
                return True
            except Exception as e:
                if "0x2" in str(e):
                    logger().info(f"Error found:{str(e)} ->"
                                  f" device already in connected step need to disconnect before connect")
                    logger().info("Initiating disconnect for cleanup")
                    self.wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
                    time.sleep(5)
                    logger().info("cfg disable")
                    # Enables the store configuration
                    self.wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
                if i == 2:
                    raise


class wifi_eap_join:
    def __init__(self, wifi_dut, wifi_access_point, eap_method):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.eap_method = eap_method

    def join_to_ap(self):
        for i in range(0, 2):
            try:
                self.wifi_dut.interfaces.wifi.associated = False
                logger().info("joining to the AP")
                # DUT connects to AP after join_ap API is executed
                self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method=self.eap_method,
                                                          timeout=40)
                return True
            except Exception as e:
                if "0x2" in str(e):
                    logger().info("Initiating disconnect for cleanup")
                    self.wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
                    time.sleep(5)
                    logger().info("cfg disable")
                    # Enables the store configuration
                    self.wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
                    if i == 2:
                        raise
                if ("0x8" in str(e)) or ("0x45" in str(e)):
                    logger().info("Connection failed ,retrying for 1 more time")
                    if i == 2:
                        raise
                else:
                    raise


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
    }
)
@pytest.mark.store_config
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
        assert status, "DUT is not responding to ping request from third party device before store configuration"

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        for count in range(0, iter_count):

            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device after store configuration"
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
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'
        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


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
        "band": 1
    }
)
@pytest.mark.store_config
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

        for count in range(0, iter_count):

            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device after store configuration"
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
        raise


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
    }
)
@pytest.mark.store_config
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

            for count in range(0, iter_count):

                for i in range(0, 3):

                    logger().info("Initiating wireless de init")
                    wifi_dut.interfaces.wifi.wireless_deinit()
                    time.sleep(2)
                    with pytest.raises(WlanError) as exc_info:
                        logger().info("Initializing the DUT")
                        wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                    if exc_info.value.error_code == 0x5A5A:
                        status = True
                        break
                    else:
                        logger().info("retrying for 3 times")
                        status = False
                        continue
                assert status, f"Wrong error code found"
                time.sleep(10)

                logger().info("getting wireless info")
                result = wifi_dut.interfaces.wifi.get_wireless_info()
                assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

                logger().info("Initiating power save")
                # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
                # DUT to power save in Wifi+bluetooth mode
                wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
                wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)

                logger().info("Initiating ping")
                # Ping to dut from third party device
                status = ping(device_ip, ping_count)
                assert status, f"DUT is not responding to ping request from third party device after store " \
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
            packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                             f'and wlan.sa == {dut_mac_address}'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 1'

            # Validating the ps poll frames
            packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter2)['packet_count'], \
                'PS-Polls not found in the sniffer capture'

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


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
@pytest.mark.store_config
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
                assert "band:2" in str(result), "dual band not found in cfg get response"
                logger().info("dual band found in cfg get response")

                logger().info("Enabling auto configuration")
                # Enable the wireless configuration in the flash
                wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

            for count in range(0, iter_count):

                for i in range(0, 3):

                    logger().info("Initiating wireless de init")
                    wifi_dut.interfaces.wifi.wireless_deinit()
                    time.sleep(2)
                    with pytest.raises(WlanError) as exc_info:
                        logger().info("Initializing the DUT")
                        wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                    if exc_info.value.error_code == 0x5A5A:
                        status = True
                        break
                    else:
                        logger().info("retrying for 3 times")
                        status = False
                        continue
                assert status, f"Wrong error code found"
                time.sleep(10)
                logger().info("getting wireless info")
                result = wifi_dut.interfaces.wifi.get_wireless_info()

                assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

                logger().info("Initiating Power save")
                # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
                # DUT to power save in Wifi+bluetooth mode
                wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
                wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)

                logger().info("Initiating Ping")
                # Ping to dut from third party device
                status = ping(device_ip, ping_count)
                assert status, f"DUT is not responding to ping request from third party device after store " \
                               f"configuration when running test  with channel {channel}"

                logger().info("Ping successful")
                wifi_dut.interfaces.wifi.associated = True
                logger().info("Initiating disconnect from DUT")
                wifi_dut.interfaces.wifi.leave()
                logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            # Validating the power management bit
            packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                             f'and wlan.sa == {dut_mac_address}'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 1'
            # Validating the ps poll frames
            packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter2)['packet_count'], \
                'PS-Polls not found in the sniffer capture'

            # wifi_dut.interfaces.wifi.inited = True

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
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,

    }
)
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "STORE_CONFIG_TEST", "passphrase": '12214040487', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_Config_LP_Power_Save_C19089(wifi_dut, wifi_access_point, wifi_sniffer):
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
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        # Enables the power Save in BT mode
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info("Enabling auto configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()

        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        time.sleep(10)
        # resetting the dut
        for count in range(0, iter_count):
            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
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

            logger().info("Initiating ping")
            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device before store configuration"
            logger().info("ping is successful")

            logger().info("Getting cfg get response")
            result = wifi_dut.interfaces.wifi.cfg_get()
            logger().info(f"cfg get command response {result}")
            logger().info("validating power mode settings in cfg get response")
            assert (("powermode:1" in str(result)) and ("ulp_mode:1" in str(result))), \
                "Expected power mode not found in cfg get response"
            logger().info("powermode:1  and ulp_mode:1 found in cfg get response")
            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {mac_address}'
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'

        # Disable store configuration
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


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
    }
)
@pytest.mark.store_config
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
        assert join_obj.join_to_ap(), "Join failed"

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
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info("Enable Auto Configuration")
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
                wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
            if exc_info.value.error_code == 0x5A5A:
                status = True
                break
            else:
                logger().info("retrying for 3 times")
                status = False
                continue
        assert status, f"Wrong error code found"
        time.sleep(10)

        logger().info("getting wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

        logger().info("Initiating ping")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device after store configuration"
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
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        logger().info(f"validating power save in sniffer with filter {packet_filter1}")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.store_config
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
        assert join_obj.join_to_ap(), "Join failed"

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
        for count in range(0, iter_count):

            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping_qos(device_ip, ping_count, qos_category="0xE0")
            assert status, "DUT is not responding to ping request from third party device after store configuration"
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
            packet_filter5 = f'(wlan.addr =={dut_mac_address} ' \
                             f'&& (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x0019))'

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
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": '123123123'})
def test_wireless_config_WPA2_C19093(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, wiseconnect_web,
                                     net_perf_client, protocol):
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
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device after store configuration"
        logger().info("ping is successful")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        # configures the values from harness on given ip address of web page
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip, \
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid, \
                                                                   security=wifi_access_point.interfaces.wifi.security, \
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )

        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert wifi_access_point.interfaces.wifi.ssid in str(result), "ssid not found in cfg get response"
        logger().info("ssid found in cfg get response")

        for count in range(0, iter_count):

            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device after store configuration"
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
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.wifi_5g
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"channel": 36})
def test_wireless_config_5GHZ_C19097(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, wiseconnect_web):
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
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")
        ping_count = 60
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device after store configuration"
        logger().info("ping is successful")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Enable wireless Configuration")
        # Save the wireless configuration in the flash
        # configures the values from harness on given ip address of web page
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip, band="5.0", \
                                                                   channel=wifi_access_point.interfaces.wifi.channel, \
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid, \
                                                                   security=wifi_access_point.interfaces.wifi.security, \
                                                                   cipher="AES", \
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )

        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert ((wifi_access_point.interfaces.wifi.ssid in str(result)) and ("band:1" in str(result)) \
                and (f"scan_cnum:{wifi_access_point.interfaces.wifi.channel}" in str(result))), \
            "expected ssid,band,channel not found in cfg get response"
        for count in range(0, iter_count):
            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device after store configuration"
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
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        logger().info(f"validating power save in sniffer with filter {packet_filter1}")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'
        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": '123123123'})
def test_wireless_config_Dual_1_C19095(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, wiseconnect_web,
                                       net_perf_client, protocol):
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
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("getting the ip")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"device ip : {device_ip}")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device after store configuration"
        logger().info("ping is successful")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        # configures the values from harness on given ip address of web page
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip, band="Dual", \
                                                                   channel=wifi_access_point.interfaces.wifi.channel,
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid, \
                                                                   security=wifi_access_point.interfaces.wifi.security, \
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )

        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert (wifi_access_point.interfaces.wifi.ssid in str(result)) and ("band:2" in str(result)) \
               and (f"scan_cnum:{wifi_access_point.interfaces.wifi.channel}" in str(result)), \
            "expected ssid,band,channel not found in cfg get response"

        for count in range(0, iter_count):

            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device after store configuration"
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
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'
        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'


    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.config('wifi_access_point',
                    wifi={"channel": 36, "security": 'WPA2', "passphrase": '123123123'})
def test_wireless_config_Dual_2_C19096(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, wiseconnect_web,
                                       net_perf_client, protocol):
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
        assert join_obj.join_to_ap(), "Join failed"

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
        wiseconnect_web.interfaces.wiseconnect_ui.configure_submit(ip_address=device_ip, band="Dual", \
                                                                   channel=wifi_access_point.interfaces.wifi.channel,
                                                                   ssid=wifi_access_point.interfaces.wifi.ssid, \
                                                                   security=wifi_access_point.interfaces.wifi.security, \
                                                                   passphrase=wifi_access_point.interfaces.wifi.passphrase
                                                                   )
        logger().info("Getting cfg get response")
        result = wifi_dut.interfaces.wifi.cfg_get()
        logger().info(f"cfg get command response {result}")
        assert (f"join_ssid:{wifi_access_point.interfaces.wifi.ssid}" in str(result)) and \
               (f"band:2" in str(result)) and (f"scan_cnum:{wifi_access_point.interfaces.wifi.channel}" in str(result)), \
            "expected ssid,band,channel not found in cfg get response"
        logger().info("ssid ,band ,channel found in cfg get response")
        for count in range(0, iter_count):
            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

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
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'
        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
                           | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        # | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.store_config
# EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678', "broadcast_ssid": False})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_store_config_in_WPA2_EAP_TLS_C19084(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, \
                                             net_perf_client, protocol, radius_server):
    try:
        testcase = "test_store_config_in_WPA2_EAP_TLS_C19084"
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        logger().info("joining to the AP")

        join_obj = wifi_eap_join(wifi_dut, wifi_access_point, eap_method="TLS")
        assert join_obj.join_to_ap(), "Join failed"
        # Get IP through DHCP
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f"Found device ip :{device_ip}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        logger().info("Enable Auto Configuration")
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
                wifi_dut.interfaces.wifi.dut_init(oper_mode=2, coex_mode=9, retries=0)
            if exc_info.value.error_code == 0x5A5A:
                status = True
                break
            else:
                logger().info("retrying for 3 times")
                status = False
                continue
        assert status, f"Wrong error code found"
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = True

        logger().info("getting wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

        logger().info("Initiating power save")
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info("Initiating ping")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device after store configuration"
        time.sleep(5)
        logger().info("Ping successful")

        iperf_tx = Wifi_data_tx(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, device_ip)
        iperf_tx.run_traffic()

        logger().info("Initiating disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'


    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
                           | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        # | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        # "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.store_config
# EAP Connection in TTLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_store_config_in_WPA2_EAP_TTLS_C19098(wifi_sniffer, wifi_access_point, wifi_dut, radius_server):
    try:
        testcase = "test_store_config_in_WPA2_EAP_TTLS_C19098"
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        join_obj = wifi_eap_join(wifi_dut, wifi_access_point, eap_method="TTLS")
        assert join_obj.join_to_ap(), "Join failed"

        # Get IP through DHCP
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f"Found device ip :{device_ip}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        for count in range(0, iter_count):
            ping_count = 60

            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=2, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)
            wifi_dut.interfaces.wifi.associated = True

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            logger().info("Initiating power save")
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Ping to dut from third party device
            status = ping(device_ip, ping_count)
            assert status, "DUT is not responding to ping request from third party device after store configuration"
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
        packet_filter1 = f'wlan.fc.type_subtype == 0x0024 and wlan.fc.pwrmgt == 1 ' \
                         f'and wlan.sa == {dut_mac_address}'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter1)['packet_count'], \
            'Sniffer validation failed for NULL data frame with PM bit 1'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                  packet_filter2)['packet_count'], \
            'PS-Polls not found in the sniffer capture'


    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
                           | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.store_config
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_store_config_error_handling_TTLS_C19083(wifi_sniffer, wifi_access_point, wifi_dut, radius_server):
    try:
        testcase = "test_store_config_error_handling_TTLS_C19083"
        validation = True

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        join_obj = wifi_eap_join(wifi_dut, wifi_access_point, eap_method="TTLS")
        assert join_obj.join_to_ap(), "Join failed"

        # Get IP through DHCP
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f"Found device ip :{device_ip}")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        wifi_access_point.interfaces.wifi.start_ap(passphrase="test123")

        for count in range(0, iter_count):

            for i in range(0, 3):

                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=2, coex_mode=9, retries=0, timeout=120)
                if (exc_info.value.error_code == 0x8) or (exc_info.value.error_code == 0x45):
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"

            wifi_dut.interfaces.wifi.associated = False

        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
                           | RS9116CustomFeatureBitMap.TriggerAutoConfiguration,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_store_config_custom_feat_bit_20_C19091(wifi_sniffer, wifi_access_point, wifi_dut):
    try:
        testcase = "test_store_config_custom_feat_bit_20_C19091"
        validation = True
        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("Getting the IP")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        ip_address = wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_address)
        logger().info(f"Found device ip : {device_ip}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device before store configuration"

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        for i in range(0, iter_count):

            for retry in range(0, 3):

                logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
                wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

                logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
                wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

                logger().info("Initiating reset")
                wifi_dut.interfaces.wifi.reset_mode = "soft"
                wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(2)

                wifi_dut.interfaces.wifi.chip_init()
                time.sleep(10)

                logger().info("stopping the capture")
                # Stop Sniffer
                wifi_sniffer.interfaces.capture.stop_capture()

                # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
                packet_filter1 = f'((wlan.fc.type_subtype == 0x0000) or (eapol) or (wlan.fc.type_subtype == 0x000b)' \
                                 f'or (wlan.fc.type_subtype == 0x0004)) and (wlan.addr == {dut_mac_address})'

                logger().info(
                    f"join packets : {wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']}")
                assert not wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                    'packet_count'], \
                    'Join procedure should not start until auto trigger enabled'

                wifi_dut.interfaces.wifi.config_auto_tigger()

                time.sleep(30)
                wifi_dut.interfaces.wifi.associated = True

                logger().info("Initiating ping")
                # Ping to dut from third party device
                status = ping(device_ip, ping_count)
                if status:
                    break
                else:
                    logger().info("retrying for auto join")
            assert status, "DUT is not responding to ping request from third party device after store configuration"
            time.sleep(5)
            logger().info("Ping successful")

            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()
            wifi_dut.interfaces.wifi.inited = True
        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
                           | RS9116CustomFeatureBitMap.TriggerAutoConfiguration,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_store_config_custom_feat_bit_20_C19092(wifi_sniffer, wifi_access_point, wifi_dut):
    try:
        testcase = "test_store_config_custom_feat_bit_20_C19092"
        validation = True
        logger().info("joining to the AP")

        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("Getting the IP")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        ip_address = wifi_dut.interfaces.wifi.start_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_address)
        logger().info(f"Found device ip : {device_ip}")

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        logger().info("Getting the DUT mac")
        dut_mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, \
            "DUT is not responding to ping request from third party device before store configuration"

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        logger().info("Initiating wireless de init")
        # deinit
        logger().info("Instead of reset need to add  wireless de init")
        wifi_dut.interfaces.wifi.reset_mode = "soft"
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(2)

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0000) or (eapol) or (wlan.fc.type_subtype == 0x000b)' \
                         f'or (wlan.fc.type_subtype == 0x0004)) and (wlan.addr == {dut_mac_address})'

        logger().info(
            f"join packets : {wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Join procedure should not start until auto trigger enabled'

        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.init()

        logger().info("joining to the AP")
        # DUT connects to AP after join_ap API is executed
        join_obj = wifi_join(wifi_dut, wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("Initiating disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.inited = True
        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise
