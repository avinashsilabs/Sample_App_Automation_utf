import pytest
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116StoreConfiguration, RS9116Region, RS9116RegionCode, RS9116ModuleType, \
    RS9116CustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116CertificateType, RS9116PowerSaveProcedureTypes, \
    RS9116ExtCustomFeatureBitMap, RS9116JoinFeatureBitMap, RS9116OperatingMode, RS9116Band
import time
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP

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

# Configuring static IP to DUT
mode = 'static'
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'


def logger():
    return get_logger(__name__)


class cleanup_store_config:
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


class VerifyJoinIp:
    def __init__(self, wifi_dut, wifi_access_point, utf_constants, store_config=False, power_save=None):
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.utf_constants = utf_constants
        self.store_config = store_config
        self.power_save = power_save

    def join_get_ip_cfg(self):

        ping_count = self.utf_constants.get("ping_count")
        logger().info("Joining to the AP")

        join_obj = wifi_join(self.wifi_dut, self.wifi_access_point)
        assert join_obj.join_to_ap(), "Join failed"

        logger().info("Getting the IP")
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        ip_address = self.wifi_dut.interfaces.wifi.start_ip(mode=9)
        # The below api parses DUTs IP address
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_address)
        logger().info(f"Found device ip : {device_ip}")

        if self.power_save:
            logger().info("initiating power save")
            self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1,
                                                     RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info("Initiating ping from remote device")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, \
            "DUT is not responding to ping request from third party device before store configuration"

        if self.store_config:
            logger().info("Enable Auto Configuration")
            # Save the wireless configuration in the flash
            self.wifi_dut.interfaces.wifi.config_save()
            # Enable the wireless configuration in the flash
            self.wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
            for count in range(0, 3):
                logger().info("Reset the DUT")
                self.wifi_dut.interfaces.wifi.reset_mode = "soft"
                self.wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.chip_init()
                time.sleep(20)
                self.wifi_dut.interfaces.wifi.associated = True
                logger().info("Initiating ping to check whether auto join is successful or not")
                # Ping to dut from third party device
                status = ping(device_ip, ping_count)
                if status:
                    break
                else:
                    logger().info("retrying for auto join")

            assert status, "DUT is not responding to ping request from third party device after store configuration"
            logger().info("Ping successful")
            logger().info("auto join is successful")
        return device_ip


def dut_clean_up(wifi_dut):
    logger().info("\n\n ---------------------------- Cleaning UP the DUT -------------------------------")
    try:
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(3)
    except:
        logger().info("******* Recovering the DUT **********")
        wifi_dut.interfaces.wifi.reset()
        wifi_dut.interfaces.wifi.inited = False
        wifi_dut.interfaces.wifi.init_with_recovery()
        time.sleep(20)
    logger().info("\n ---------------------------- Cleaning UP of DUT is Completed -------------------")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_Config_AT_C101942(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut):
    try:
        testcase = "test_Store_Config_AT_101942"
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing cwith Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants, store_config=True)
        device_ip = wifi_obj.join_get_ip_cfg()

        logger().info("Initiating disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.inited = True
        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping the capture")
        # Stop Sniffer
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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.dut("rs9116")
@pytest.mark.AT
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_Config_powersave_C101943(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut):
    try:
        testcase = "test_Store_Config_powersave_C101943"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants, store_config=True,
                                power_save=1)
        device_ip = wifi_obj.join_get_ip_cfg()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put

        logger().info("Initiating disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()

        wifi_dut.interfaces.wifi.inited = True

        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping the capture")
        # Stop Sniffer
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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_AT_C101944(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                      remote_socket):
    try:
        testcase = "test_Store_IP_PORT_TCP_AT_C101944"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
        device_ip = wifi_obj.join_get_ip_cfg()

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(port=5001)
        time.sleep(5)

        tcp_socket = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", "1")
        wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket, "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA")
        wifi_dut.interfaces.wifi.close_socket(tcp_socket)

        wifi_dut.interfaces.wifi.inited = True

        # Stop Sniffer
        logger().info("stopping the capture")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_Transp_AT_C101945(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                         wifi_client, remote_socket):
    try:
        testcase = "test_Store_IP_PORT_Transp_AT_C101945"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
        device_ip = wifi_obj.join_get_ip_cfg()

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(port=5001)
        time.sleep(5)

        wifi_dut.interfaces.wifi.trans_mode_params(512, "@", 100, 150, 200, 4, 0, 2731, 1, "0.0.0.0", 1, 0, 0, 0)
        wifi_dut.interfaces.wifi.send_trasp_data(data="MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA",
                                                 success_response="")
        time.sleep(2)
        wifi_dut.interfaces.wifi.send_trasp_data(data="@@@", success_response="AT+RSI_TMODE\x01")
        wifi_dut.interfaces.wifi.inited = True

        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_diff_indeces_AT_C101946(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                                   wifi_client, remote_socket):
    try:
        index_list = [0, 1, 2, 3]
        testcase = "test_Store_IP_PORT_TCP_AT_C101946"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        for index in index_list:
            wifi_dut.interfaces.wifi.store_server_ip_port(index, host_ip, 5001)

            wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
            device_ip = wifi_obj.join_get_ip_cfg()

            logger().info("Starting tcp server remotely at port number 5001")
            remote_socket.interfaces.socket.start_server(port=5001)
            time.sleep(5)

            sock_decr = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", index)
            wifi_dut.interfaces.wifi.send_tcp_data(sock_decr, "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQ")
            wifi_dut.interfaces.wifi.close_socket(sock_decr)
            remote_socket.interfaces.socket.stop()
            wifi_dut.interfaces.wifi.inited = True

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678", "dtim": 10,
                                               "beacon_interval": 200})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_Transp_diff_indeces_AT_C101947(rs_helper, utf_constants, wifi_sniffer, wifi_access_point,
                                                      wifi_dut, wifi_client, remote_socket):
    try:
        index_list = [0, 1, 2, 3]
        testcase = "test_Store_IP_PORT_Transp_diff_indeces_AT_C101947"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        for index in index_list:
            remote_socket.interfaces.socket.time_limit = 1000
            logger().info("Starting tcp server remotely at port number 5001")
            remote_socket.interfaces.socket.start_server(port=5001)
            wifi_dut.interfaces.wifi.store_server_ip_port(index, host_ip, 5001)
            wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
            device_ip = wifi_obj.join_get_ip_cfg()

            wifi_dut.interfaces.wifi.trans_mode_params(512, "@", 100, 150, 200, 4, 0, 2731, index, "0.0.0.0", 1, 0, 0,
                                                       0)
            wifi_dut.interfaces.wifi.send_trasp_data(data="MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA",
                                                     success_response="")
            time.sleep(2)
            wifi_dut.interfaces.wifi.send_trasp_data(data="@@@", success_response="AT+RSI_TMODE\x01")
            remote_socket.interfaces.socket.stop()
            wifi_dut.interfaces.wifi.inited = True

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_worng_index_AT_C101948(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                                  wifi_client,
                                                  remote_socket):
    testcase = "test_Store_IP_PORT_TCP_worng_index_AT_C101948"
    validation = True
    logger().info("joining to the AP")
    ping_count = utf_constants.get("ping_count")
    logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')

    with pytest.raises(WlanError) as exc_info:
        logger().info("Initializing the DUT")
        wifi_dut.interfaces.wifi.store_server_ip_port(6, host_ip, 5001)
    assert exc_info.value.error_code == 0xff24, "set store server ip command should fail when wrong index is set"

    logger().info("stopping the capture")
    # Stop Sniffer
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_data_AT_C101949(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                           wifi_client, remote_socket):
    try:
        testcase = "test_Store_IP_PORT_TCP_data_AT_C101949"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        remote_socket.interfaces.socket.time_limit = 5000

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
        device_ip = wifi_obj.join_get_ip_cfg()

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(port=5001)
        time.sleep(5)

        tcp_socket = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", "1")
        sw = Stopwatch()
        while sw.elapsed_sec < 3600:
            wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket, "hello")
            time.sleep(1)
        wifi_dut.interfaces.wifi.close_socket(tcp_socket)
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.inited = True

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_CFG_AT_C101950(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                          wifi_client, remote_socket):
    try:
        testcase = "test_Store_IP_PORT_TCP_CFG_AT_C101950"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants, store_config=True)
        device_ip = wifi_obj.join_get_ip_cfg()

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(port=5001)
        time.sleep(5)

        tcp_socket = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", "1")
        wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket, "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA")
        wifi_dut.interfaces.wifi.close_socket(tcp_socket)
        remote_socket.interfaces.socket.stop()
        logger().info("Initiating disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.inited = True
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_Transp_CFG_AT_C101958(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                             wifi_client,
                                             remote_socket):
    try:
        testcase = "test_Store_IP_PORT_Transp_CFG_AT_C101958"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")

        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants, store_config=True)
        device_ip = wifi_obj.join_get_ip_cfg()

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(port=5001)
        time.sleep(5)

        wifi_dut.interfaces.wifi.trans_mode_params(512, "@", 100, 150, 200, 4, 0, 2731, 1, "0.0.0.0", 1, 0, 0, 0)
        wifi_dut.interfaces.wifi.send_trasp_data(data="MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA",
                                                 success_response="")
        time.sleep(2)
        wifi_dut.interfaces.wifi.send_trasp_data(data="@@@", success_response="AT+RSI_TMODE\x01")
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(5)
        wifi_dut.interfaces.wifi.inited = True
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_Transp_CFG_PING_AT_C101952(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                                  wifi_client,
                                                  remote_socket):
    try:
        testcase = "test_Store_IP_PORT_Transp_CFG_PING_AT_C101952"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

        wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants, store_config=True)
        device_ip = wifi_obj.join_get_ip_cfg()

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(port=5001)
        time.sleep(5)

        wifi_dut.interfaces.wifi.trans_mode_params(512, "@", 100, 150, 200, 4, 0, 2731, 1, "0.0.0.0", 1, 0, 0, 0)
        wifi_dut.interfaces.wifi.send_trasp_data(data="MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA",
                                                 success_response="")
        time.sleep(2)
        wifi_dut.interfaces.wifi.send_trasp_data(data="@@@", success_response="AT+RSI_TMODE\x01")
        remote_socket.interfaces.socket.stop()

        logger().info("Initiating ping from remote device")
        # Ping to dut from third party device
        status = ping(device_ip, ping_count)
        assert status, \
            "DUT is not responding to ping request from third party device before store configuration"

        wifi_dut.interfaces.wifi.leave()
        time.sleep(5)
        wifi_dut.interfaces.wifi.inited = True
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": 0,
        "ext_custom_features": 0,
        "ext_tcpip_features": 0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": 0,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_SSL_AT_C101951(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                          wifi_client,
                                          remote_socket):
    testcase = "test_Store_IP_PORT_TCP_SSL_AT_C101951"
    validation = True
    logger().info("joining to the AP")
    ping_count = utf_constants.get("ping_count")
    logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')

    wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

    wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
    device_ip = wifi_obj.join_get_ip_cfg()

    logger().info("Starting tcp server remotely at port number 5001")
    remote_socket.interfaces.socket.start_server(port=5001)
    time.sleep(5)

    with pytest.raises(WlanError) as exc_info:
        logger().info("Initializing the DUT")
        tcp_socket = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", "1",
                                                                     local_port=1234, tos=0,
                                                                     tls_ws_enable=1)
    assert exc_info.value.error_code == 0xff82, "tcp connection should fail with error code 0xff82"

    remote_socket.interfaces.socket.stop()

    logger().info("Initiating disconnect from DUT")
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.inited = True

    logger().info("stopping the capture")
    # Stop Sniffer
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_4_sock_CFG_AT_C101960(rs_helper, utf_constants, wifi_sniffer, wifi_access_point,
                                                 wifi_dut, wifi_client, remote_socket_factory):
    try:
        testcase = "test_Store_IP_PORT_TCP_4_sock_CFG_AT_C101960"
        validation = True
        logger().info("joining to the AP")
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')
        start_port = 5000
        tcp_socket = []
        for sock_count in range(0, 4):
            port = start_port + sock_count
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            logger().info(f"Starting tcp server remotely at port number {port}")
            server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
            time.sleep(5)
            logger().info(f"storing the socket {sock_count} params")
            wifi_dut.interfaces.wifi.store_server_ip_port(sock_count, host_ip, port)
            if sock_count == 0:
                wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants, store_config=True)
                device_ip = wifi_obj.join_get_ip_cfg()
            logger().info(f"Starting tcp client {sock_count} at dut side with stored ip and port")
            sock_desc = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", sock_count,
                                                                        local_port=2571 + sock_count)
            tcp_socket.insert(sock_count, sock_desc)
            logger().info(f"sending data over socket {sock_count}")
            wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                                   "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")
            logger().info(f"sending data over socket {sock_count}")
            wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                                   "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")

            if sock_count == 3:
                time.sleep(100)
                for sock in tcp_socket:
                    logger().info("closing tcp socket")
                    wifi_dut.interfaces.wifi.close_socket(sock)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        logger().info("Initiating disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("stopping the capture")
        wifi_dut.interfaces.wifi.inited = True
        # Stop Sniffer
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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_2_sock_AT_C101956(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                             wifi_client,
                                             remote_socket_factory):
    testcase = "test_Store_IP_PORT_TCP_2_sock_AT_C101956"
    validation = True
    logger().info("joining to the AP")
    ping_count = utf_constants.get("ping_count")
    logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')

    start_port = 5000

    tcp_socket = []

    for sock_count in range(0, 2):
        port = start_port + sock_count
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.time_limit = 3600
        logger().info(f"Starting tcp server remotely at port number {port}")
        server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
        time.sleep(5)

        logger().info(f"storing the socket {sock_count} params")
        wifi_dut.interfaces.wifi.store_server_ip_port(sock_count, host_ip, port)

        if sock_count == 0:
            wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
            device_ip = wifi_obj.join_get_ip_cfg()

        logger().info(f"Starting tcp client {sock_count} at dut side with stored ip and port")
        sock_desc = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", sock_count,
                                                                    local_port=2571 + sock_count)
        tcp_socket.insert(sock_count, sock_desc)
        logger().info(f"sending data over socket {sock_count}")
        wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                               "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")

        if sock_count == 0:
            logger().info("Initiating power save")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            logger().info(f"sending data over socket {sock_count}")
            wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                                   "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")

        if sock_count == 1:

            time.sleep(100)

            for sock in tcp_socket:
                logger().info("closing tcp socket")
                wifi_dut.interfaces.wifi.close_socket(sock)

    remote_socket_factory.interfaces.socket.close_all()
    remote_socket_factory.interfaces.socket.sockets = []

    logger().info("Initiating disconnect from DUT")
    wifi_dut.interfaces.wifi.leave()

    wifi_dut.interfaces.wifi.inited = True

    logger().info("stopping the capture")
    # Stop Sniffer
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_4_sock_AT_C101957(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                             wifi_client, remote_socket_factory):
    testcase = "test_Store_IP_PORT_TCP_4_sock_AT_C101957"
    validation = True
    logger().info("joining to the AP")
    ping_count = utf_constants.get("ping_count")
    logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')

    start_port = 5000

    tcp_socket = []

    for sock_count in range(0, 4):
        port = start_port + sock_count
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.time_limit = 3600
        logger().info(f"Starting tcp server remotely at port number {port}")
        server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
        time.sleep(5)

        logger().info(f"storing the socket {sock_count} params")
        wifi_dut.interfaces.wifi.store_server_ip_port(sock_count, host_ip, port)

        if sock_count == 0:
            wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
            device_ip = wifi_obj.join_get_ip_cfg()

        logger().info(f"Starting tcp client {sock_count} at dut side with stored ip and port")
        sock_desc = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", sock_count,
                                                                    local_port=2571 + sock_count)
        tcp_socket.insert(sock_count, sock_desc)
        logger().info(f"sending data over socket {sock_count}")
        wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                               "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")
        if sock_count == 0:
            logger().info("Initiating power save")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info(f"sending data over socket {sock_count}")
            wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                                   "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")

        if sock_count == 3:
            time.sleep(100)
            for sock in tcp_socket:
                logger().info("closing tcp socket")
                wifi_dut.interfaces.wifi.close_socket(sock)

    remote_socket_factory.interfaces.socket.close_all()
    remote_socket_factory.interfaces.socket.sockets = []

    logger().info("Initiating disconnect from DUT")
    wifi_dut.interfaces.wifi.leave()

    wifi_dut.interfaces.wifi.inited = True

    logger().info("stopping the capture")
    # Stop Sniffer
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890", "interface": "wlan0"}
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_Store_IP_PORT_AP_TCP_C101953(wifi_sniffer, net_perf_client, wifi_dut, wifi_client,
                                      channel, utf_constants, remote_socket):
    ping_count = utf_constants.get("ping_count")
    testcase = "test_Store_IP_PORT_AP_TCP_C101953"

    ip_dict = wifi_dut.interfaces.wifi.ip
    if not ip_dict:
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                         static_subnet=static_subnet, static_gateway=static_gateway)
        time.sleep(5)
        logger().info(f"********** DUT works as a Ap mode *********")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)

    logger().info(f"********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    logger().info("********** wifi_client is joining to DUT(works as a Ap mode) *********")
    time.sleep(20)
    wifi_client.interfaces.wifi.join(ssid="Store_AP")
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info("***** starting Ping *****")
    status = ping(device_ip, ping_count)
    assert status == True, f"Ping failed"
    logger().info("***** Ping successful *****")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')

    logger().info("Starting tcp server remotely at port number 5001")
    remote_socket.interfaces.socket.start_server(server_ip=host_ip, port=5001)
    time.sleep(10)
    wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)
    tcp_socket = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", "1")
    wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket, "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA")
    time.sleep(10)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket)
    wifi_client.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.inited = True
    logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890", "interface": "wlan0"}
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_Store_IP_PORT_AP_3_TCP_SOCK_C101954(wifi_sniffer, net_perf_client, wifi_dut,
                                             wifi_client, channel, utf_constants,
                                             remote_socket_factory):
    ping_count = utf_constants.get("ping_count")
    testcase = "test_Store_IP_PORT_AP_3_TCP_SOCK_C101954"

    ip_dict = wifi_dut.interfaces.wifi.ip
    if not ip_dict:
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                         static_subnet=static_subnet, static_gateway=static_gateway)
        time.sleep(5)
        logger().info(f"********** DUT works as a Ap mode *********")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)

    logger().info(f"********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    logger().info("********** wifi_client is joining to DUT(works as a Ap mode) *********")
    time.sleep(20)
    wifi_client.interfaces.wifi.join()
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info("***** starting Ping *****")
    status = ping(device_ip, ping_count)
    assert status == True, f"Ping failed"
    logger().info("***** Ping successful *****")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')
    start_port = 5000
    tcp_socket = []
    for sock_count in range(0, 3):
        port = start_port + sock_count
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.time_limit = 3600
        logger().info(f"Starting tcp server remotely at port number {port}")
        server_socket.start_server(server_ip=host_ip, port=port, socket_type=SOCKET_TYPE_TCP)
        time.sleep(10)
        logger().info(f"storing the socket {sock_count} params")
        wifi_dut.interfaces.wifi.store_server_ip_port(sock_count, host_ip, port)

        logger().info(f"Starting tcp client {sock_count} at dut side with stored ip and port")
        sock_desc = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", sock_count,
                                                                    local_port=2571 + sock_count)
        tcp_socket.insert(sock_count, sock_desc)
        logger().info(f"sending data over socket {sock_count}")
        wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                               "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")
        logger().info(f"sending data over socket {sock_count}")
        wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                               "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")
        if sock_count == 2:
            time.sleep(100)

            for sock in tcp_socket:
                logger().info("closing tcp socket")
                wifi_dut.interfaces.wifi.close_socket(sock)

    remote_socket_factory.interfaces.socket.close_all()
    remote_socket_factory.interfaces.socket.sockets = []

    wifi_client.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.inited = True
    logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890", "interface": "wlan0"}
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_Store_IP_PORT_AP_CFG_TCP_C101959(wifi_sniffer, net_perf_client, wifi_dut, wifi_client,
                                          channel, utf_constants, remote_socket):
    try:
        ping_count = utf_constants.get("ping_count")
        testcase = "test_Store_IP_PORT_AP_CFG_TCP_C101959"
        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet, static_gateway=static_gateway)
            time.sleep(5)
            logger().info(f"********** DUT works as a Ap mode *********")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)

        logger().info(f"********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        logger().info("********** wifi_client is joining to DUT(works as a Ap mode) *********")
        time.sleep(20)
        wifi_client.interfaces.wifi.join()
        logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
        device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {device_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        logger().info("Reset the DUT")
        wifi_dut.interfaces.wifi.reset_mode = "soft"
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(2)
        wifi_dut.interfaces.wifi.chip_init()
        time.sleep(10)
        wifi_client.interfaces.wifi.join()

        logger().info("***** starting Ping *****")
        status = ping(device_ip, ping_count)
        assert status == True, f"Ping failed"
        logger().info("***** Ping successful *****")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(server_ip=host_ip, port=5001)
        time.sleep(10)

        tcp_socket = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", "1")
        wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket, "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA")
        wifi_dut.interfaces.wifi.close_socket(tcp_socket)
        logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.inited = True
        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
            clean_up.dut_recovery()
        clean_up.disconnect()
        raise


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "Store_AP", "passphrase": "1234567890", "interface": "wlan0"}
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_Store_IP_PORT_AP_3_TCP_SOCK_CFG_C101961(wifi_sniffer, net_perf_client, wifi_dut,
                                                 wifi_client, channel, utf_constants,
                                                 remote_socket_factory):
    try:
        ping_count = utf_constants.get("ping_count")
        testcase = "test_Store_IP_PORT_AP_3_TCP_SOCK_CFG_C101961"

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet, static_gateway=static_gateway)
            time.sleep(5)
            logger().info(f"********** DUT works as a Ap mode *********")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)

        logger().info(f"********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        logger().info("********** wifi_client is joining to DUT(works as a Ap mode) *********")
        time.sleep(20)
        wifi_client.interfaces.wifi.join()
        logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
        device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {device_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        start_port = 5000
        tcp_socket = []
        for count in range(0, 3):
            port = start_port + count
            logger().info(f"storing the socket {count} params")
            wifi_dut.interfaces.wifi.store_server_ip_port(count, host_ip, port)

        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        logger().info("Reset the DUT")
        wifi_dut.interfaces.wifi.reset_mode = "soft"
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(5)
        wifi_dut.interfaces.wifi.chip_init()
        time.sleep(10)
        wifi_client.interfaces.wifi.join()
        logger().info("***** starting Ping *****")
        status = ping(device_ip, ping_count)
        assert status == True, f"Ping failed"
        logger().info("***** Ping successful *****")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Fetching the host ip address...{host_ip}')
        start_port = 5000
        tcp_socket = []
        for sock_count in range(0, 3):
            port = start_port + sock_count
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            logger().info(f"Starting tcp server remotely at port number {port}")
            server_socket.start_server(server_ip=host_ip, port=port, socket_type=SOCKET_TYPE_TCP)
            time.sleep(20)
            logger().info(f"storing the socket {sock_count} params")
            wifi_dut.interfaces.wifi.store_server_ip_port(sock_count, host_ip, port)

            logger().info(f"Starting tcp client {sock_count} at dut side with stored ip and port")
            sock_desc = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", sock_count,
                                                                        local_port=2571 + sock_count)
            tcp_socket.insert(sock_count, sock_desc)
            logger().info(f"sending data over socket {sock_count}")
            wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                                   "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")
            logger().info(f"sending data over socket {sock_count}")
            wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket[sock_count],
                                                   "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQU")
            if sock_count == 2:
                time.sleep(100)

                for sock in tcp_socket:
                    logger().info("closing tcp socket")
                    wifi_dut.interfaces.wifi.close_socket(sock)

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.inited = True
        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        time.sleep(2)
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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
                           | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 1,
    }
)
@pytest.mark.AT
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 36})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated", "disable_store_config"])
def test_Store_IP_PORT_TCP_A7_5G_AT_C101955(rs_helper, utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                            wifi_client,
                                            remote_socket):
    testcase = "test_Store_IP_PORT_TCP_A7_5G_AT_C101955"
    validation = True
    logger().info("joining to the AP")
    ping_count = utf_constants.get("ping_count")
    logger().info(f"Configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f'Fetching the host ip address...{host_ip}')

    wifi_dut.interfaces.wifi.store_server_ip_port(1, host_ip, 5001)

    wifi_obj = VerifyJoinIp(wifi_dut, wifi_access_point, utf_constants)
    device_ip = wifi_obj.join_get_ip_cfg()

    logger().info("Starting tcp server remotely at port number 5001")
    remote_socket.interfaces.socket.start_server(port=5001)
    time.sleep(5)

    tcp_socket = wifi_dut.interfaces.wifi.open_tcp_client_socket("0.0.0.0", "1")
    wifi_dut.interfaces.wifi.send_tcp_data(tcp_socket, "MNHFDSGSAJGsky8erekefWLDUQUFQEFHJGDQURYQRHWQHFQFAFAFHAFAFA")
    wifi_dut.interfaces.wifi.close_socket(tcp_socket)

    logger().info("Initiating disconnect from DUT")
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.inited = True

    logger().info("stopping the capture")
    # Stop Sniffer
    wifi_sniffer.interfaces.capture.stop_capture()
