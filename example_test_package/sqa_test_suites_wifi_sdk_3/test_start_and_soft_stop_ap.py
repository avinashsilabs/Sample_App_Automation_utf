import time
import pytest
from utf.utf_config import UtfConfig
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI

def logger():
    return get_logger(__name__)



"""Test Author = Jyothi Nagireddy
        1. Start the sniffer before connection
        2. Initiate connection from Wifi client(Raspberry)
        4. Initiate ping from the wifi client
        5. Disconnect the wifi client
        6. Stop the sniffer capture 
        7. Analysing all sniffer capture packets.
setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4 - 2 and more                                                           
        3. Access Point(Third Party AP's)
"""


class ApModeConnections(ThreadBase):
    def __init__(self, wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point,
                 sl_collections, utf_constants,  testcase_no=None,
                 dtim_period=None, beacon=None, ping=True):
        self.wifi_dut = wifi_dut
        self.wifi_clients = wifi_clients
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.utf_constants = utf_constants
        self.testcase_no = testcase_no
        self.dtim_period = dtim_period
        self.beacon = beacon
        self.ping = ping

    def run(self):
        if self.testcase_no == 191344:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "8"
            self.dtim_count = "4"
            self.beacon_interval = "100"
            self.no_of_clients = 2

        if self.testcase_no == 191349:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "8"
            self.dtim_count = "3"
            self.beacon_interval = "100"
            self.no_of_clients = 2


        self.ping_count = self.utf_constants.get("ping_count")
        ipconfig = self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password, channel=self.channel,
                                          dtim_beacon_count=self.dtim_count,
                                          beacon_interval=self.beacon_interval)
        time.sleep(5)
        for i in range(0, self.no_of_clients):
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{self.dut_mac_address}**********")
        self.dut_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ipconfig)
        logger().info(f"*********Device ip : {self.dut_ip}**********")


        if self.ping == True:
            for i in range(0, 1):
                for count in range(3):
                    try:
                        client_ip = self.wifi_clients[i+1].interfaces.wifi.get_ip_address()
                        logger().info(f"Client_ip: {client_ip}")
                        rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                            f"sudo ping -c {self.ping_count} {client_ip}")
                        assert rc == 0, f"{self.wifi_clients[i + 1]} failed to ping DUT"
                        logger().info(f"\n{stdout}\n")
                        logger().info(f"Ping successful from wifi client 1(STA1) to wifi client(STA2)")
                        break
                    except:
                        logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                        time.sleep(10)
                for i in range(0, 1):
                    for count in range(3):
                        try:
                            client_ip = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                            logger().info(f"Client_ip: {client_ip}")
                            rc, stdout, stderr = self.wifi_clients[i+1].interfaces.wifi.shell.execute(
                                f"sudo ping -c {self.ping_count} {client_ip}")
                            assert rc == 0, f"{self.wifi_clients[i + 1]} failed to ping DUT"
                            logger().info(f"\n{stdout}\n")
                            logger().info(f"Ping successful from wifi client 2(STA2) to wifi client 1(STA1)")
                            break
                        except:
                            logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                            time.sleep(10)
    def concurrent_conn(self):
        self.ping_count = self.utf_constants.get("ping_count")
        logger().info(f"....Scanning for AP nearby.....")
        self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(".... Connecting to Wi-Fi AP....")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, pmk_enable=False)
        logger().info("....DUT configures the IP Address....")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version='ipv4')
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"*************device ip : {self.device_ip}*****************")
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{self.dut_mac_address}**********")
        status = ping(self.device_ip, 10)
        assert status, f"failed ping to dut"
        if self.ping is True:
            for i in range(len(self.wifi_clients)):
                rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                    f"sudo ping -c {self.ping_count} {self.device_ip}")
                assert rc == 0, f"{self.wifi_clients[i + 1]} failed to ping DUT"
                logger().info(f"\n{stdout}\n")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8, "beacon": 100
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_soft_stop_ap_functionality_after_enabling_start_ap_C191344(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify whether DUT is able stop AP after enabling start AP"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191344.pcap")
        time.sleep(3)
        ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                                utf_constants,
                                                testcase_no=191344, ping=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        logger().info(f"stop the AP")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(5)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Checking deauthentication in sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_mac_address,
            filter_name='deauthentication')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauthentication in Sniffer'
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8, "beacon": 100
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_able_restart_to_with_different_beacon_intervals_C191345(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify whether DUT is able to restart with different beacon interval's"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191345.pcap")
        time.sleep(3)
        ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                       utf_constants,
                                       testcase_no=191344, ping=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        time.sleep(3)
        logger().info(f"stop the AP")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                               channel=channel,
                                               dtim_beacon_count=4,
                                               beacon_interval=300)
        time.sleep(10)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Checking deauthentication in sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_mac_address,
            filter_name='deauthentication')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauthentication in Sniffer'
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_mac_address, radio_ch=channel, beacon=300,
            filter_name='beacon_ap_mode_dtim_interval')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon_ap_mode_dtim_interval in Sniffer'
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info(f"Clean up activity")
        logger().info(f"stop the AP as ap start initiated")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8, "beacon": 100
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [8])
def test_dut_able_restart_with_invalid_beacon_interval_C191347(wifi_sniffer, net_perf_client, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify whether DUT is able to restart with invalid beacon interval"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191347.pcap")
        time.sleep(3)
        ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                       utf_constants,
                                       testcase_no=191344, ping=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        logger().info(f"stop the AP")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(5)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info(f"Checking deauthentication in sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_mac_address,
            filter_name='deauthentication')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauthentication in Sniffer'
        logger().info(" ********** restarting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=4,
                                          beacon_interval=1200)
    except Exception as Err:
        if "0x10062" in str(Err):
            logger().info(f"expected error code: {Err}")
        else:
            raise Err


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8, "beacon": 100
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_able_to_restart_with_different_dtim_intervals_C191349(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify whether DUT is able to restart with different DTIM interval's"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191349.pcap")
        time.sleep(3)
        ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                       utf_constants,
                                       testcase_no=191349, ping=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        time.sleep(3)
        logger().info(f"stop the AP")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=5,
                                          beacon_interval=100)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Checking deauthentication in sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_mac_address,
            filter_name='deauthentication')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauthentication in Sniffer'
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_mac_address, radio_ch=channel, dtim_period=5,
            filter_name='beacon_ap_mode_dtim_period')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon_ap_mode_dtim_period in Sniffer'
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Clean up activity")
        logger().info(f"stop the AP")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8, "beacon": 100
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_soft_start_and_stop_ap_in_multiple_iterations_C191351(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify the DUT behavior while doing start and stop AP in multiple iterations"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191351.pcap")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=3,
                                          beacon_interval=100)
        time.sleep(3)
        for i in range(5):
            time.sleep(20)
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            time.sleep(5)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                                   channel=channel,
                                                   dtim_beacon_count=3,
                                                   beacon_interval=300)
            logger().info(f"**************iteration: {i}*************")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_mac_address}**********")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # logger().info(f"Checking deauthentication in sniffer")
        # packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
        #     sa_addr=dut_mac_address,
        #     filter_name='deauthentication')
        # assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        #     'Unable to find  deauthentication in Sniffer'
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Clean up activity")
        logger().info(f"stop the AP")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8, "beacon": 100
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_giving_soft_stop_ap_for_second_time_C191355(wifi_sniffer, net_perf_client, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel):
    """Check DUT is throwing error or not while giving stop AP API for the second time without giving START AP"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191355.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=3,
                                          beacon_interval=100)
        logger().info(f"Stop the Ap for 1st time")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info(f"Stop the Ap for 2nd time")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Err:
        if "0xb44" in str(Err):
            logger().info(f"expected error code: {Err}")
        else:
            raise Err


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_soft_start_ap_stop_ap_with_different_dtim_intervals_C191362(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify whether DUT is able to restart with different DTIM interval's in concurrent mode"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191362.pcap")
        time.sleep(3)
        ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                       utf_constants, ping=False)
        ap_dut_obj.concurrent_conn()
        logger().info(f"*********start the ap***********")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=3,
                                          beacon_interval=100)
        logger().info(f"*********stop the ap***********")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info(f"*********restart the ap***********")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=5,
                                          beacon_interval=100)
        ap_addr = ap_dut_obj.dut_mac_address.split(":")
        ap_mac = int(ap_addr[5][1]) + 1
        ap_mac_addr = ap_dut_obj.dut_mac_address[:-1] + str(ap_mac)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Checking deauthentication in sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_mac_address,
            filter_name='deauthentication')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauthentication in Sniffer'
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac_addr, radio_ch=channel, dtim_period=5,
            filter_name='beacon_ap_mode_dtim_period')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon_ap_mode_dtim_period in Sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Clean up activity")
        logger().info(f"*********stop the ap as start ap initiated***********")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_soft_start_ap_stop_ap_with_different_beacon_intervals_C191359(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify whether DUT is able to restart with different beacon interval's in concurrent mode"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191359.pcap")
        time.sleep(3)
        ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                       utf_constants, ping=False)
        ap_dut_obj.concurrent_conn()
        logger().info(f"*********start the ap***********")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=3,
                                          beacon_interval=100)
        logger().info(f"*********stop the ap***********")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info(f"*********restart the ap***********")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=3,
                                          beacon_interval=300)
        ap_addr = ap_dut_obj.dut_mac_address.split(":")
        ap_mac = int(ap_addr[5][1])+1
        ap_mac_addr = ap_dut_obj.dut_mac_address[:-1]+str(ap_mac)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac_addr, radio_ch=channel, beacon=300,
            filter_name='beacon_ap_mode_dtim_interval')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon_ap_mode_dtim_interval in Sniffer'
        logger().info(f"Checking deauthentication in sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_mac_address,
            filter_name='deauthentication')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauthentication in Sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Clean up activity")
        logger().info(f"*********stop the ap as start ap initiated***********")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_soft_start_and_stop_ap_in_multiple_iterations_C191363(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify the DUT behavior while doing start and stop AP along with STA connect & disconnect in multiple iterations in concurrent mode"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191363.pcap")
        time.sleep(3)
        for i in range(5):
            logger().info(f"*********start the ap***********")
            wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                              channel=channel,
                                              dtim_beacon_count=3,
                                              beacon_interval=100)
            logger().info(f"Stop the Ap for 1st time")
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            logger().info(f"*********restart the ap***********")
            wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                              channel=channel,
                                              dtim_beacon_count=5,
                                              beacon_interval=100)
            ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                           utf_constants, ping=False)
            ap_dut_obj.concurrent_conn()
            logger().info(f"********Disconnection**********")
            wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info(f"Clean up activity")
        logger().info(f"Stop the Ap as start ap initiated")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "8",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.parametrize("channel", [8])
def test_wifi_sdk_dut_soft_start_ap_stop_ap_with_invalid_beacon_interval_C191360(wifi_sniffer, wifi_dut, wifi_clients,
                                           utf_constants, sl_collections, sniffer_filter, channel, wifi_access_point):
    """Verify whether DUT is able throw error or not when we are trying to bringing up the AP with invalid Beacon interval in concurrent mode"""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C191360.pcap")
        time.sleep(3)
        ap_dut_obj = ApModeConnections(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                       utf_constants, ping=False)
        ap_dut_obj.concurrent_conn()
        logger().info(f"*********start the ap***********")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=channel,
                                          dtim_beacon_count=4,
                                          beacon_interval=1200)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Checking deauthentication in sniffer")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_mac_address,
            filter_name='deauthentication')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauthentication in Sniffer'

    except Exception as Err:
        if "0x10062" in str(Err):
            logger().info(f"expected error code: {Err}")
        else:
            raise Err

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



