import time
import pytest
from utf.interfaces.wifi import WlanError
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap, RS9116CoexMode, RS9116ConfigFeatureBitMap,
    RS9116StoreConfiguration, RS9116PowerSaveModes, RS9116DataRate)
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants

"""Test Author = Jyothi Nagireddy
 
        1. Start the sniffer before connection
        2. Required A7 EVK(DUT) board 
        3. Stop the sniffer
        4. Initiate ping from the dut
        5. Analysing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT
        2. EFR32
        3. Raspberry PI4 - 2 and more
        4. Access Point(Third Party AP's)
"""

def logger():
    return get_logger(__name__)

# Configuring static IP to DUT
mode = 'static'
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'

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


class ApMode_SingleClientConn(ThreadBase):
    def __init__(self, wifi_dut, wifi_client, utf_constants,  ssid=None, channel=None,  dtim_count=None, beacon_interval=None, leave=True):
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.utf_constants = utf_constants
        self.ssid = ssid
        self.channel = channel
        self.dtim_count = dtim_count
        self.beacon_interval = beacon_interval
        self.leave = leave

    def run(self):
        ping_count = self.utf_constants.get("ping_count")
        dut_ip = self.wifi_dut.interfaces.wifi.ip
        logger().info(f"********* Dut IP **********: {dut_ip}")
        if not dut_ip:
            logger().info("********* configuring static ip to DUT *********")
            self.wifi_dut.interfaces.wifi.start_ip(0, "A", static_ip=static_ip, static_subnet=static_subnet, static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        self.wifi_dut.interfaces.wifi.start_ap(0, "A", ssid=self.ssid, channel=self.channel, dtim_beacon_count=self.dtim_count, beacon_interval=self.beacon_interval)
        logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
        self.wifi_client.interfaces.wifi.join(0, "A", ssid=self.ssid)
        time.sleep(10)
        dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(0, "A", 'utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"Initiating wlan ping from client '{self.wifi_client.name}' to DUT")
        client_ip = self.wifi_client.interfaces.wifi.get_ip_address(0, "A")
        logger().info(f"********* Client IP **********: {client_ip}")
        rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(0, "A", f"sudo ping -c {ping_count} {dut_ip}")
        logger().info(f"\n{stdout}\n")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address(0, "A")
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        if self.leave:
            logger().info(f'Disconnecting from DUT-AP')
            self.wifi_client.interfaces.wifi.leave(0, "A")
        return dut_mac_address, dut_ip

class ApMode_MultipleClientsConn(ThreadBase):
    def __init__(self, wifi_dut, wifi_clients, utf_constants,  ssid=None, channel=None,  dtim_count=None, beacon_interval=None, leave=True):
        self.wifi_dut = wifi_dut
        self.wifi_clients = wifi_clients
        self.utf_constants = utf_constants
        self.ssid = ssid
        self.channel = channel
        self.dtim_count = dtim_count
        self.beacon_interval = beacon_interval
        self.leave = leave

    def run(self):
        ping_count = self.utf_constants.get("ping_count")
        assert len(self.wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        dut_ip = self.wifi_dut.interfaces.wifi.ip
        logger().info(f"********* Dut IP **********: {dut_ip}")
        if not dut_ip:
            logger().info("********* configuring static ip to DUT *********")
            self.wifi_dut.interfaces.wifi.start_ip(0, "B",static_ip=static_ip, static_subnet=static_subnet,
                                              static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        self.wifi_dut.interfaces.wifi.start_ap(0, "B", ssid=self.ssid, beacon_interval=self.beacon_interval, channel=self.channel)
        time.sleep(10)
        logger().info(f"********** Number of wifi_clients are:{len(self.wifi_clients)} **********")
        for i in range(0, len(self.wifi_clients)):
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join(0, "B", ssid=self.ssid, channel=self.channel, passphrase="123456789")
            time.sleep(5)
            dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(0, "B",'utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(0, "B"
                        f"sudo ping -c {ping_count} {dut_ip}")
                    logger().info(f"\n{stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(0, "B")
        logger().info(f"****************dut mac mac : {dut_mac_address} ************************")
        logger().info("Waiting 30 seconds to check connection stability")
        time.sleep(30)
        logger().info("Checking the connection stability after 30 seconds")
        for i in range(0, len(self.wifi_clients)):
            logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
            rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(0, "B"
                f"sudo ping -c {ping_count} {dut_ip}")
            logger().info(f"\n{stdout}\n")
            logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")
        if self.leave:
            for i in range(0, len(self.wifi_clients)):
                logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
                self.wifi_clients[i].interfaces.wifi.leave(0, "B")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19454", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_ap_mode_tx_rules_USregion_C19454(wifi_dut, wifi_clients, channel, wifi_sniffer,  sl_collections, utf_constants, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_c19454")
        time.sleep(3)
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_clients, ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_frame_region_US")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region US in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19456", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "JP",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [13])
def test_wifi_sdk_ap_mode_tx_rules_JPregion_C19456(wifi_dut, wifi_client, channel, wifi_sniffer, wifi_clients, utf_constants, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_c19456")
        time.sleep(3)
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_clients, ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_frame_region_JP")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region JP in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19455", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "EU",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [13])
def test_wifi_sdk_ap_mode_tx_rules_EUregion_C19455(wifi_dut, wifi_client, channel, wifi_sniffer, wifi_clients, utf_constants, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_c19454")
        time.sleep(3)
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_clients, ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_frame_region_EU")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region EU in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("dtim_period", [1, 2, 3, 6, 10])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_various_dtim_intervals_C19444(wifi_sniffer, wifi_dut, wifi_client, channel,
                                              utf_constants, ssid, dtim_period):
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        file_name = f'test_DTIM_{dtim_period}_C19444'
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        time.sleep(3)
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, dtim_count=dtim_period, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="mgmt_probe_auth_Assoc_req_eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="dtim_period")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            f'Unable to find dtim period: {dtim_period} in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19443", "passphrase": "12345678",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19443",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("beacon", [100, 200, 600, 1000])
@pytest.mark.parametrize("channel", [11])
# beacon interval 600, 1000 not working
def test_wifi_sdk_DUTAP_diff_beacon_intervals_C19443(wifi_sniffer, wifi_dut, wifi_client, beacon, channel,
                                            utf_constants, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        if beacon in [600, 1000]:
            pytest.skip(
                   f"Beacon interval '{beacon}' not working, Raspi-STA is not finding DUT-AP for beacon interval '{beacon}'")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        file_name = f'test_beacon_{beacon}_C19443'
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        time.sleep(3)
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, beacon_interval=beacon, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_frame")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon frame in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            f'Unable to find dtim period: {beacon} in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19432", "passphrase": "12345678",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_DUPAP_multiclient_connect_disconnect_C19432(firmware_loader, wifi_sniffer, wifi_dut, wifi_clients, channel,
                                                     utf_constants, sl_collections, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_C19432")
        time.sleep(3)
        wlan_obj1 = ApMode_MultipleClientsConn(wifi_dut, wifi_clients, utf_constants,
                                               ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon interval in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="mgmt_probe_auth_Assoc_req_eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            f'Unable to find probe request in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19430_C19442", "passphrase": "12345678", "region_config": 0,
        "beacon": 100,
        "region_code_ap": "US",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wifi_sdk_Max_STAs_connect_and_ping_C19430_C19442(wifi_sniffer, wifi_dut, wifi_clients, channel,
                                                          utf_constants, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_c19430")
        time.sleep(3)
        wlan_obj1 = ApMode_MultipleClientsConn(wifi_dut, wifi_clients,  utf_constants,
                                               ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon interval in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="mgmt_probe_auth_Assoc_req_eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'unable to find Probe Request & Authentication Req & Association Req & EAPOL'

    finally:
         logger().info("\n******Stop Sniffer finally******")
         wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19437", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19437",
        "passphrase": "123456789",
        "interface": "wlan0",
        "channel": 10,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [10])
def test_wifi_sdk_apmode_connectivity_with_wrong_psk_Cli_C19437(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel):
    try:
        #thread not used
        dut_ip = wifi_dut.interfaces.wifi.ip
        logger().info(f"********* Dut IP **********: {dut_ip}")
        if not dut_ip:
           logger().info("********* configuring static ip to DUT *********")
           wifi_dut.interfaces.wifi.start_ip(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_apmode_connectivity_with_wrong_psk_Cli19437')
        time.sleep(3)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        time.sleep(5)
        try:
            logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
            wifi_client.interfaces.wifi.join()
            time.sleep(5)
        except:
            logger().info(f"connectivity fails as PSK is given wrong -->Expected")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="deauth")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  deauth packet in Sniffer'
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="disassociation")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  disassoc in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ", "channel": 14,

    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_wifi_sdk_DUTAP_USregion_unsupported_channel_C19458(wifi_dut, wifi_sniffer, channel):
    try:
        #thread not used
        dut_ip = wifi_dut.interfaces.wifi.ip
        logger().info(f"********* Dut IP **********: {dut_ip}")
        if not dut_ip:
            logger().info("********* configuring static ip to DUT *********")
            wifi_dut.interfaces.wifi.start_ip(static_ip=static_ip, static_subnet=static_subnet, static_gateway=static_gateway)
        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_apmode_connectivity_with_wrong_psk_Cli19437')
        time.sleep(3)
        with pytest.raises(WlanError) as exc_info:
            logger().info(" ********** Starting DUT as an AP with region as US and channel as 14 ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            logger().info(f"error code received:{exc_info.value.error_code}")
        assert exc_info.value.error_code == 0xA, "Did not receive the desired error code from DUT, failing the test"
        logger().info("Found the desired error code 0xA, marking the test case passed")

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19447", "passphrase": "12345678", "dtim": 4,
        "region_code_ap": "US ",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19447",
        "passphrase": "12345678",
        "interface": "wlan0",
        "channel": 11,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("beacon", [100, 200, 300])
def test_wifi_sdk_DUTAP_TCP_Tx_Rx_C19447(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol,
                                channel, beacon, utf_constants, ssid, sl_collections):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C19447_{beacon}")
        time.sleep(3)
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        # iperf code
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="mgmt_probe_auth_Assoc_req_eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  HT_IE in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="HT_IE")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find  HT_IE in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find  beacon interval in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19436", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19436",
        "passphrase": "12345678",
        "channel": 10,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.parametrize("channel", [10])
# @pytest.mark.firmware_app("test_ap_ht_caps")
def test_wifi_sdk_DUTAP_verify_beacon_format_C19436(wifi_sniffer, wifi_dut, wifi_client, channel,
                                           utf_constants, sl_collections, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19436')
        time.sleep(3)
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
         # wifi_dut.interfaces.wifi.set_htcaps()
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_frame")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon frame in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find  beacon interval in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="mgmt_probe_auth_Assoc_req_eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter3)['packet_count'], \
            'Unable to find  beacon interval in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="HT_IE")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter4)['packet_count'], \
            'Unable to find  HT_IE in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19446", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "dtim": 4,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19446",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
# @pytest.mark.firmware_app("test_ap_ht_caps")
def test_wifi_sdk_DUT_APMode_11n_htcaps_support_C19446(wifi_sniffer, wifi_dut, wifi_client, channel, protocol, sl_collections, ssid):
    try:
        wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=2048, buffer_len=128)
        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19446')
        time.sleep(3)
        logger().info(" ********** Starting DUT as an AP ********* ")
        # wifi_dut.interfaces.wifi.set_htcaps()
        wlan_obj1 = ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=True)
        dut_mac_address, device_ip = wlan_obj1.start()
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wlan_obj1.wait_for_exit()
        #iperf code
        logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
        wifi_client.interfaces.wifi.leave()
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="beacon_frame")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon frame in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="mgmt_probe_auth_Assoc_req_eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find  HT_IE in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name="HT_IE")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter3)['packet_count'], \
            'Unable to find  HT_IE in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

