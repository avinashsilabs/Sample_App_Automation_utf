import time
import pytest
import ipaddress
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xMqttQos
)
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig

def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcpv6 and get IPV6 address
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from/to the dut to IPV6 address
        5. scan ,connect, data transfer
        6. ble connection slave/master
        
        

    Author: Swathi.Chinthala

"""
import ipaddress
import random


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr

class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, test_type=None, ping_from="remote", ping_count=10, addr_type="global"):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.test_type = test_type
        self.dut_add_dict = None
        self.addr_type = addr_type
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def ping_async(self):

        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.addr_type)
        ip_addr = ipaddress.ip_address(remote_ip)
        logger().info(f"Remote device ip:{ip_addr}")
        logger().info(f"Ping from DUT to remote")
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, num_ping_attempts=self.ping_count,
                                           ping_timeout=10,  ip_version='ipv6', ping_size=64)
        time.sleep(10)
        logger().info(f"Ping successful")

    def run(self):

        self.dut_add_dict = self.sl_collections.\
            join_to_wifi_network(wifi_dut=self.wifi_dut,
                                 wifi_access_point=self.wifi_access_point,
                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                 ip_version='ipv6',
                                 ping_after_power_save=False,
                                 ping_before_power_save=False,
                                 power_save=self.power_save,
                                 ipv6_type=self.addr_type
                                 )
        logger().info(
            f"DUT MAC ADDRESS :  {self.dut_add_dict['dut_mac_address']} "
            f"DUT IPV6 ADDRESS : {self.dut_add_dict['device_ip']}")

        if self.test_type == "ping":

            if self.ping_from == "remote":

                device_ip = self.dut_add_dict['device_ip']

                if self.addr_type == "link":
                    interface = self.wifi_client.interfaces.wifi.config["interface"]
                    device_ip = f"{self.dut_add_dict['device_ip']}%{interface}"

                logger().info("ping from remote to DUT")
                status = self.sl_collections.ping(device_ip=device_ip,
                                                  ping_count=self.ping_count,
                                                  retry_count=3)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info("ping successful")

            if self.ping_from == "dut":
                self.ping_async()

            if self.ping_from == "both":
                self.ping_async()
                logger().info("ping from remote to DUT")
                status = self.sl_collections.ping(device_ip=self.dut_add_dict['device_ip'],
                                                  ping_count=self.ping_count)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info("ping successful")



# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        ble_client=None,
        ble_test_type=None,
        sl_collections=None,
        ble_scan_type=1,
        ble_pairing=0,
        dev_state=8
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing
        self.dev_state = dev_state

        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(
            set_smp=self.ble_pairing
        )
        assert (
            self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_client_address = None

    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        self.ble_client.interfaces.bluetooth.close()

    def stop_scan_adv(self):
        logger().info("Initiating stop scan from dut")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()
        self.ble_client.interfaces.bluetooth.close()

    def ble_disconnect(self, disconnect_from="remote"):

        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == self.dev_state, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        self.ble_client.interfaces.bluetooth.close()

    def advertise_remote_device(self):
        self.ble_client_address = self.sl_collections.advertise_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def advertise_dut(self):
        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def scan_and_connect_from_remote(self):
        self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            dev_state=self.dev_state
        )

    def scan_and_connect_from_dut(self):
        self.sl_collections.scan_and_connect_from_dut(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_client_address=self.ble_client_address,
            dev_state=self.dev_state
        )

    def run(self):
        if self.ble_test_type == "advertise":
            self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                timeout=20,
            )

        if self.ble_test_type == "scan":
            self.sl_collections.check_ble_scan_functionality(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_address=self.ble_dut_address,
                ble_scan_type=self.ble_scan_type,
                timeout=60,
            )
        if self.ble_test_type == "start_scan_stop_scan":
            # Start scanning
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=self.ble_client_address, timeout=60
            )
            logger().info(
                f"Remote device found in scan results ,BLE scanning is successful"
            )
            # Stop scanning
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        if self.ble_test_type == "slave" or self.ble_test_type == "master":
            self.ble_client_address = self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                mode=self.ble_test_type,
                ble_pairing=self.ble_pairing,
                dev_state=self.dev_state
            )
        if self.ble_test_type == "scan_from_remote_device":
            self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
            )

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()

        if self.ble_test_type == "scan_and_connect_from_remote":
            self.scan_and_connect_from_remote()





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
        | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv",
                      "ble_stop_scan"]
)
def test_Coex_sdk_WLAN_ipv6_BLE_master_C156991(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. advertise remote device
        4. Scan & connect from DUT to remote
        5. Join the access point and get ipv6 address
        6. Enable wlan and bt power save mode in dut after the connection
        7. Ping from AP backend machine to DUT's IPV6 Address.


    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client,
                              addr_type="link")
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=9
        )
        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_advertising = True
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv",
                      "ble_stop_scan"]
)
def test_Coex_sdk_WLAN_ipv6_BLE_slave_C156992(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise DUT
        4. Join the access point and get ipv6 address
        5. Enable wlan and bt power save mode in dut after the connection
        6. Scan from remote BLE device and connect to remote

    """

    try:
        assert len(ble_clients) == 2, f"2 Raspi devices needed"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              test_name=test_name, sl_collections=sl_collections, test_type="ping",
                              ping_count=ping_count, wifi_client=wifi_client)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            dev_state=10
        )

        ble_obj.advertise_dut()
        sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_scanning = True
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_Coex_sdk_WLAN_ipv6_BLE_adv_scan_C156989(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. scan& Join to the access point and enable the dhcp
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate ping from the dut

    """
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    logger().info(
        "start capturing with Sniffer by giving the test case name as filename"
    )

    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          test_name=test_name, sl_collections=sl_collections, test_type="ping",
                          ping_count=ping_count, wifi_client=wifi_client, addr_type="link")
    ble_obj = BleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        sl_collections=sl_collections,
        ble_test_type="advertise",
    )
    ble_obj.start()
    ble_obj.wait_for_exit()
    ble_client.interfaces.bluetooth.stop_scanning()
    ble_client.interfaces.bluetooth.close()
    sl_collections.check_ble_scan_functionality(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        ble_address=ble_obj.ble_dut_address,
        timeout=60,
    )
    wlan_obj.start()
    wlan_obj.wait_for_exit()
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    wifi_dut.interfaces.wifi.ble_stop_advertising()
    ble_client.interfaces.bluetooth.stop_advertising()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer validation is successful")
    wifi_dut.interfaces.wifi.leave()





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode
        | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA3", "passphrase": "1234567890", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"),
                               }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_Coex_sdk_WLAN_ipv6_BLE_adv_scan_C156990(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. scan& Join to the access point and enable the dhcp
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate ping from the dut

    """
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    test_type = "ping"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    logger().info(
        "start capturing with Sniffer by giving the test case name as filename"
    )

    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          test_name=test_name, sl_collections=sl_collections, test_type="ping",
                          ping_count=ping_count, wifi_client=wifi_client)
    wlan_obj.start()
    wlan_obj.wait_for_exit()

    ble_obj = BleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        sl_collections=sl_collections,
        ble_test_type="advertise",
    )
    ble_obj.start()
    ble_obj.wait_for_exit()
    ble_client.interfaces.bluetooth.stop_scanning()
    ble_client.interfaces.bluetooth.close()
    sl_collections.check_ble_scan_functionality(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        ble_address=ble_obj.ble_dut_address,
        timeout=60,
    )
    logger().info("ping from remote to DUT")
    status = sl_collections.ping(device_ip=wlan_obj.dut_add_dict['device_ip'],
                                 ping_count=ping_count,
                                 retry_count=3)
    assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
    logger().info("ping successful")
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    wifi_dut.interfaces.wifi.ble_stop_advertising()
    ble_client.interfaces.bluetooth.stop_advertising()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer validation is successful")
    wifi_dut.interfaces.wifi.leave()


