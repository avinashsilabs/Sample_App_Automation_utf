import time
import pytest
import re

from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    SocketType,
    Cipher,
    RS9116AsyncEventType,
    RS9116StoreConfiguration,
    RS9116CustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    RS9116MqttQos,
    DeviceConstants,
)
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import get_host_ip
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
import string
import random
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band


def logger():
    return get_logger(__name__)


ping_count = 60


# this thread used for Wi-Fi join
class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, testcase=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, test_type=False, iteration=1):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.iteration = iteration

    def run_traffic(self, device_ip):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        logger().info("starting the server from Remote device")

        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip,
                                                             protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()
        # self.net_perf_client.interfaces.net_perf.client_options["time"] = 50

        logger().info("sending data from DUT")
        # open socket and send traffic
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")

    def run(self):

        validation = True

        logger().info(f"starting the sniffer in channel {self.wifi_access_point.interfaces.wifi.channel}")

        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.testcase}_beacons")

        time.sleep(10)

        ##validating beacons from AP

        packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {self.wifi_access_point.interfaces.wifi.bssid})'

        logger().info("stopping the sniffer")

        self.wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating beacons in sniffer with filter : {}".format(packet_filter1))
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "Beacons not found in sniffer capture"

        for count in range(0, self.iteration):

            logger().info("starting the sniffer again")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)

            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

            # bles the scan in dut on channel
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

            logger().info(f"scan results : {scan_results}")
            assert (len(scan_results) >= 1), "Scan failed"

            # Join Wi-Fi Access Point
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info(f"Successfully connected to AP")

            # This API Enables the DHCP in DUT
            ip_config = self.wifi_dut.interfaces.wifi.start_ip()

            device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"Found device ip: {device_ip}")

            # Fetches the DUT mac address
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {ap_bssid}")

            logger().info("Initiating power save")
            logger().info("enabling wifi power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')

            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")

            if self.test_type == "iperf":
                logger().info("Running data transfer")
                self.run_traffic(device_ip)

            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

            logger().info("stopping the sniffer capture")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
            packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and  ' \
                             f'((wlan.fc.type_subtype == 0x0000) or (wlan.fc.type_subtype==0x0001) ) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b) or (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], "packets not found"
            logger().info("sniffer validation is successful")


def ping_from_client(wifi_client, dut_ip, ping_count=10):
    logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to DUT")
    client_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Client IP **********: {client_ip}")
    for count in range(3):
        try:
            rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dut_ip}")
            assert rc == 0
            logger().info(f"\n{stdout}\n")
            return rc == 0
        except:
            time.sleep(10)


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "band": 0,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_firmware_version_C34753(wifi_dut):
    expected_version = parse_version()
    if expected_version is None:
        pytest.skip("No firmware version for 9116x in manifest, skipping test_version")
    logger().info(f"Expected Firmware version: {expected_version}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual Firmware version: {result}")
    assert result == expected_version, "Expected Firmware version and Actual firmware version are not matching"


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "region": 'Asia'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_join_WORLD_2_4_C34788(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_WORLD_2_4_C34788"
    test_type = "None"
    logger().info("DUT set to Region -. World domain")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, net_perf_client,
                                 protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "band": 0,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "region": 'Europe'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_join_EU_2_4_C34786(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_EU_2_4_C34786"
    test_type = "None"
    logger().info("Setting the DUT to Region Europe")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,
                                 net_perf_client, protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "band": 0,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "region": 'US'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_join_US_2_4_C34785(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_US_2_4_C34785"
    test_type = "None"

    logger().info("Setting the DUT to Region US")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,
                                 net_perf_client, protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '123456789'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Connectivity_with_WPA2_security_AP_C34757(wifi_access_point, wifi_dut, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_WPA2_security_AP')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save')

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()

        logger().info(f"dut_mac_address : {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_mac_address : {ap_bssid}")

        ## Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and  ' \
                         f'((wlan.fc.type_subtype == 0x0000) or (wlan.fc.type_subtype==0x0001) ) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) or (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        #assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        #    'packet_count'], 'Unable to find power management bit 1 in sniffer'

        logger().info("disconnecting to ap.....")
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Associated and ping in {t.duration} seconds")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.WiFiClient,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19449", "passphrase": "test1234", "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19449",
        "passphrase": "123456789",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'external_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_DUT_soft_reset_sta_to_ap_C19449(wifi_sniffer, wifi_dut, wifi_client, channel,
                                         wifi_access_point,
                                         utf_constants):
    ping_count = utf_constants.get("ping_count")
    validation = True
    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_softreset_statoap_C19449')
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid, channel=channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("DUT-STA joining into Wi-Fi")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    dut_ip_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f'dut ip is :{dut_ip_as_client}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    status = ping(dut_ip_as_client, ping_count)
    assert status, f"DUT failed to ping AP"

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating probe request packet in sniffer")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 && wlan.sa=={dut_mac_address} && wlan.da==ff:ff:ff:ff:ff:ff'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        "Unable to find probe req from dut in sniffer"

    logger().info("Validating assoc request,response and eapol packets in sniffer")
    packet_filter2 = f'(wlan.addr=={dut_mac_address})&&(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        "Unable to find assoc req or resp packet in Sniffer"

    logger().info("Validating qos data packets")
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.type_subtype == 0x0028)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets in sniffer'

    # logger().info("passing passphrase and ssid to decrypt dhcp packets")
    # decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    # logger().info(f"decryption_key is '{decryption_key}'")
    # status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    # logger().info(f'DHCP packet from DUT found: {status}')
    # assert status, "DHCP packet not found"

    # deinit
    logger().info("Initiating wireless de init")
    wifi_dut.interfaces.wifi.deinit()

    logger().info("Initiating wireless init to change DUT STA mode to AP Mode ")
    # wifi_dut.interfaces.wifi.dut_init(oper_mode=6, coex_mode=9, retries=3)

    wifi_dut.interfaces.wifi.inited = False
    wifi_dut.interfaces.wifi.init(mode='ap')

    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer when DUT is in AP mode ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_Trnms_rules_USregion_C19449')
    time.sleep(3)

    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_C19449", beacon_interval=100, channel=channel)
    time.sleep(10)

    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19449", channel=channel, passphrase="123456789")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    rasp_mac = wifi_client.interfaces.wifi.get_mac_address()
    logger().info(f"raspi_mac:{rasp_mac}")
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info(" ********** Starting ping ********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")

    packet_filter3 = f'wlan.fc.type_subtype == 0x0008 && wlan.sa=={dut_mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)["packet_count"], \
        "Unable to find beacon frame from DUT  in Sniffer"


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Connectivity_with_11n_only_mode_AP_C19707(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    validation = True

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_11n_only_mode_AP_C19707')

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-ASUS-hidden", "broadcast_ssid": False})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Connectivity_with_hidden_mode_AP_C19708(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    validation = True

    logger().info(" ====== configuring the Sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_hidden_mode_AP_C19708')

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)

    # Validate hidden mode
    packet_filter4 = f'(wlan.ssid == "") and (wlan.fc.type_subtype == 0x0008 and (wlan.sa == {ap_mac}) )'

    logger().info(" Validate hidden ssid, authentication and association keys")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find hidden in sniffer '


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Join_time_providing_PSK_C19712(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    validation = True
    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
    time_obj = FilterPacket()

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Join_time_providing_PSK_C19712')

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {wifi_access_point.interfaces.wifi.bssid})'

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calcuting the reponse time of eapol4
    time_str2 = time_stamp_list[1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    assert time_taken <= 0.4
    logger().info(f"time taken to connect is: {time_taken}")


@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'test123@random'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Joining_by_rsi_psk_command_C19714(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    validation = True

    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Joining_by_rsi_psk_command_C19714')

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


@pytest.mark.config('wifi_access_point', wifi=
{"ssid": "Testssid", "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnmkloirgrgrtyuio1234567890o", "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_psk_with_64_different_characters_C19719(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    validation = True

    wifi_dut.interfaces.wifi.associated = False

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_psk_with_64_different_characters_C19719')

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)


@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "security": 'WPA2', "channel": 7})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_Init_Scan_Join_Disconnect_30min_C19710(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants):
    with TimeMeasurer() as t:
        t_end = time.time() + 60 * 30
        while time.time() < t_end:
            validation = True
            logger().info(" ====== configuring the sniffer with the access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Init_Scan_Join_Disconnect_30min_C19710')

            wifi_dut.interfaces.wifi.associated = False

            device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
            logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

            ap_mac = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP MAC : {ap_mac}")

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            rs_helper.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_mac)

            logger().info("disconnecting to ap.....")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    logger().info(f"Associated and ping in {t.duration} seconds")
