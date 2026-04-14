import random
import string
import time

import pytest
from utf.interfaces.iperf import IperfConstants
import threading
from example_test_package.sqa_test_suites_wifi_sdk_3.ble_standalone.functional.ble_data_transfer_sdk.test_ble_data_transfer_sdk import Ble_Data_Transfer
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_dle_sdk import BleThread
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble_ipv6.test_sta_ble_ipv6 import HttpDownload
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
from utf.utf_config import UtfConfig
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
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
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf.utils.stopwatch import Stopwatch

def logger():
    return get_logger(__name__)


# Global objects for cleanup
ble_obj = None
wifi_obj = None

class IndicationThread(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.sl_collections = None
        self.ble_ready_event = threading.Event()
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):

        # Ensure DUT bluetooth interface alias exists
        logger().info("Ensuring DUT bluetooth interface alias exists")
        if not hasattr(self.wifi_dut.interfaces, "bluetooth"):
            self.wifi_dut.interfaces.bluetooth = self.wifi_dut.interfaces.wifi

        ble_obj = Ble_Data_Transfer(self.wifi_dut, self.ble_client, self.sl_collections)
        ble_dut_address = ble_obj.ble_gatt_init(set_smp=1)
        self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=0, smp_auth_req_bonding=1,
                                                      smp_auth_req_mitm=1, smp_auth_req_sc=0,
                                                      smp_max_enc_key_size=16,
                                                      smp_local_oob_data_flag_not_present=0,
                                                      smp_enc_key=1, smp_id_key=1, smp_sign_key=1)

        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        data_length = len(data)

        # Create Custom services on DUT
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0x1AA1)
        logger().info("Adding custom characteristic declaration to the custom service")
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
        logger().info("Adding characteristic value attribute to the service")
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")

        # Adv Remote device
        ble_obj.advertising_remote()
        time.sleep(2)

        # Start scan and connect from dut
        ble_obj.scan_conn_from_dut_device()

        # Confirm BLE connected
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1

        if state_int == 8:
            logger().info("BLE link established. Signaling ready.")
            self.ble_ready_event.set()
        else:
            raise Exception("BLE did not reach connected state")

        # Get All Profiles
        char_path, char_props = ble_obj.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)

        # # Configure Buffer Mode
        ble_obj.configure_buffer_mode(mode=1, count=2)

        logger().info(f"****** Indication Start****************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                char_uid=char_uid)
        logger().info("Subscribed to notifications successfully")
        indication_count = 0
        sw = Stopwatch()
        while sw.elapsed_sec < 300:
            self.wifi_dut.interfaces.wifi.ble_indicate_value(ble_remote_dev_address=ble_obj.ble_client_address,
                                                        handle=12, data=data, data_length=data_length)
            indication_count += 1
            time.sleep(5)

        logger().info(f"Total indications sent: {indication_count}")
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Total notifications received: {len(notifications)}")
        try:
            assert len(notifications) == indication_count
        except:
            assert len(notifications) == indication_count - 1

        logger().info(f"Received Notifications : : {notifications}")

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(1)
        logger().info("******************** ble_remove_service ***********************")
        self.wifi_dut.interfaces.wifi.ble_remove_service()


class WpsJoinThread(ThreadBase):
    """Thread class for WPS PBC WiFi connection"""

    def __init__(
            self,
            wifi_dut=None,
            wifi_access_point=None,
            sl_collections=None,
            auto_connect=True,
            ip_version='ipv4',
            ipv6_type='global',
            ping_count=10,
            timeout=120,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.auto_connect = auto_connect
        self.ip_version = ip_version
        self.ipv6_type = ipv6_type
        self.ping_count = ping_count
        self.timeout = timeout
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"WPS Join Thread initialized with auto_connect={auto_connect}, ip_version={ip_version}")

    def run(self):
        """Execute WPS PBC connection"""

        # First
        try:
            if not self.wifi_dut.interfaces.wifi.associated:
                # Start WPS push button on AP first
                logger().info("Starting WPS push button process on Access Point")
                self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
                time.sleep(2)  # Give AP time to start WPS

                # Scan for APs
                logger().info("Scanning for APs")
                scan_status, scan_results = self.sl_collections.scan(
                    self.wifi_dut, scan_status=False, retry_count=3, channel=0
                )
                assert scan_status, f"Scanning for AP failed with reason: {scan_results}"
                logger().info(f"Scan results: {scan_results}")

                self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
                logger().info(f"DUT MAC ADDRESS: {self.dut_mac_address}")

                # Initiate WPS push button join from DUT
                logger().info("Initiating WPS push button connection from DUT")
                self.wifi_dut.interfaces.wifi.start_client_wps(
                    interface="client",
                    wps_role=1,  # 1-Enrollee
                    wps_mode=0,  # 0-PBC
                    auto_connect=self.auto_connect
                )
                logger().info("WPS push button connection initiated successfully")

                # Wait for connection to establish
                max_wait_time = self.timeout  # WPS can take up to 2 minutes
                wait_interval = 2
                elapsed_time = 0
                while elapsed_time < max_wait_time:
                    if self.wifi_dut.interfaces.wifi.associated:
                        logger().info("DUT successfully connected to AP via WPS")
                        break
                    time.sleep(wait_interval)
                    elapsed_time += wait_interval
                else:
                    assert False, f"WPS connection timed out after {max_wait_time} seconds - DUT did not associate with AP"

                # Configure IP
                ip_status, ip_config = self.sl_collections.configure_ip(
                    self.wifi_dut, ip_status=False, retry_count=3, ip_version=self.ip_version
                )
                assert ip_status, f"Unable to assign IP ADDRESS through DHCP with reason: {ip_config}"

                if self.ip_version == 'ipv4':
                    self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                else:
                    if self.ipv6_type == 'global':
                        self.device_ip = ip_config[1] if len(ip_config) > 1 else ip_config[0]
                    else:
                        self.device_ip = ip_config[0]

                logger().info(f"DUT IP: {self.device_ip}")
                self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
                logger().info(f"AP BSSID: {self.ap_mac_address}")

                # Ping to DUT
                logger().info(f"Pinging DUT at {self.device_ip}")
                ping_status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=self.ping_count)
                assert ping_status, "DUT NOT RESPONDING FOR PING REQUEST"

                # Enable power save if configured
                if self.power_save:
                    logger().info("Applying performance profile mode: power_save_low_latency")
                    self.wifi_dut.interfaces.wifi.set_performance_profile(
                        mode="power_save_low_latency",
                        dtim_aligned_type=0,
                        num_of_dtim_skip=0,
                        listen_interval=0,
                        monitor_interval=0
                    )
                    self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                        psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                        psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave
                    )
                    logger().info("Pinging DUT after power-save")
                    ping_status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=self.ping_count)
                    assert ping_status, "DUT NOT RESPONDING FOR PING REQUEST AFTER POWER SAVE"

            else:
                logger().info("Device is already connected with AP")
                self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip()
                self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
                self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid

        except Exception as e:
            logger().info(f"WPS join failed: {str(e)}")
            raise

def wifi_dut_marker(
        ext_custom_bit=0,
        tcp_feat_bit=0,
        ext_tcp_feat_bit=0,
        wifi_stack_len=3584,
        ble_stack_len=3584,
        num_peripheral_connections=1,
        num_central_connections=1,
        wifi_thread_count=1,
        ble_thread_count=1,
):
    """Pytest marker for WiFi DUT configuration"""
    config = {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | tcp_feat_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | ext_tcp_feat_bit,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | ext_custom_bit,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=num_central_connections)
                        | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=num_peripheral_connections)
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
                        | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
                        | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                   | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": wifi_thread_count, "stack_len": wifi_stack_len, "priority": 8},
            "ble": {"count": ble_thread_count, "stack_len": ble_stack_len, "priority": 8},
        },
    }
    return pytest.mark.config("wifi_dut", wifi=config)


def join_to_wifi_network_via_wps(wifi_dut=None, wifi_access_point=None, power_save=True,
                                 mode='power_save_low_latency', channel=0,
                                 ping_count=10, retry_count=1, ping_after_power_save=True, ping_before_power_save=True,
                                 associated=None,
                                 dtim_aligned_type=0, num_of_dtim_skip=0, listen_interval=0, monitor_interval=0,
                                 ip_version='ipv4', tcp_ip_bypass=False, ip_config_disable=False,
                                 ipv6_type='global', skip_scan=False, sl_collections=None):
    """
    This function is responsible to connect DUT with AP using WPS Push Button Configuration
    :param wifi_dut: DUT device object
    :param wifi_access_point: Access Point object
    :param power_save: Enable power save mode
    :param mode: Power save mode type
    :param channel: WiFi channel
    :param ping_count: Number of ping packets
    :param retry_count: Retry count for operations
    :param ping_after_power_save: Ping after enabling power save
    :param ping_before_power_save: Ping before enabling power save
    :param associated: Current association status
    :param dtim_aligned_type: DTIM alignment type
    :param num_of_dtim_skip: Number of DTIM to skip
    :param listen_interval: Listen interval
    :param monitor_interval: Monitor interval
    :param ip_version: IP version ('ipv4' or 'ipv6')
    :param tcp_ip_bypass: Bypass TCP/IP configuration
    :param ip_config_disable: Disable IP configuration
    :param ipv6_type: IPv6 type ('global' or 'link_local')
    :param skip_scan: Skip WiFi scan
    :return: Dictionary containing 'device_ip' and 'dut_mac_address'
    """
    dut_add_dict = {}

    if associated is False:
        # Start WPS push button on AP first
        logger().info("Starting WPS push button process on Access Point")
        # wifi_access_point.start_wps_process_push()
        wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
        time.sleep(2)  # Give AP time to start WPS

        # Scan for APs if not skipped
        if skip_scan is False:
            scan_status, reason = sl_collections.scan(wifi_dut, scan_status=False, retry_count=retry_count,
                                                      channel=channel)
            assert scan_status, f"....Scanning for AP failed..with reason: {reason}...."

        # Initiate WPS push button join from DUT
        logger().info("Initiating WPS push button connection from DUT")
        try:
            wifi_dut.interfaces.wifi.start_client_wps(
                interface="client",
                wps_role=0,  # 1-Enrollee
                wps_mode=0,  # 0-PBC
                auto_connect=True
            )
            logger().info("WPS push button connection initiated successfully")
            wifi_dut.interfaces.wifi.associated = True
        except Exception as e:
            logger().error(f"WPS connection failed: {str(e)}")
            raise

        logger().info("DUT successfully connected to AP via WPS")
        dut_add_dict['dut_mac_address'] = wifi_dut.interfaces.wifi.get_mac_address()

        if not (tcp_ip_bypass or ip_config_disable):
            # configure_ip tries to assign IP ADDRESS through DHCP
            ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=retry_count,
                                                               ip_version=ip_version)
            assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

            if ip_version == 'ipv4':
                device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            else:
                if ipv6_type == 'global':
                    device_ip = ip_config[1]
                else:
                    device_ip = ip_config[0]

            logger().info(f"DUT ip: {device_ip}")

            # we fetch the ip address and mac_address
            dut_add_dict['device_ip'] = device_ip

            logger().info(
                f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']} DUT IP ADDRESS : {dut_add_dict['device_ip']}")

            # ping to DUT before power_save
            if ping_before_power_save:
                status = sl_collections.ping(device_ip=dut_add_dict['device_ip'], ping_count=ping_count)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if power_save:
            logger().info(f"....Applying performance profile mode : {mode}")
            wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip,
                                                             listen_interval, monitor_interval)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            if not tcp_ip_bypass:
                if ping_after_power_save:
                    logger().info("....Pinging DUT after power-save....")
                    status = sl_collections.ping(device_ip=dut_add_dict['device_ip'], ping_count=ping_count)
                    assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        return dut_add_dict
    else:
        logger().info(f'\n\n *** Device is already connected with AP *** \n\n')
        return None


# Test Case 1: BLE dual role with Tx&Rx notifications while WLAN (WPS auto connect enabled) with TCP data transfer
@wifi_dut_marker(num_peripheral_connections=1, num_central_connections=1, ble_thread_count=2, ble_stack_len=3584,
                 wifi_stack_len=3584)
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913649')
def test_coex_sdk_wps_pbc_ble_dual_tx_rx_tcp_auto_connect_enabled_C913649(
        wifi_dut,
        ble_clients,
        wifi_access_point,
        request,
        wifi_client,
        utf_constants,
        sl_collections,
        net_perf_client,
        protocol
):
    """
    Verify BLE dual role connections with TX & Rx notifications while WLAN (connection established via WPS)
    with auto connect enabled and TCP data transfer

    Preconditions:
        - Configure the AP with WPA2 security
        - BLE Connection Interval = 250 ms
        - Enable data transfer parameters for BLE
    """
    # global ble_obj, wifi_obj
    ble_clients_address = []
    ble_dut_address = None
    try:
        assert len(ble_clients) >= 2, "Minimum 2 Raspi devices needed"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        conn_interval = 250

        # Start BLE GATT on DUT
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        # -------------------- RX notify thread --------------------
        svc = "HealthThermometerService"
        charc = "CustomNotifyCharacteristic"
        data_rx = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info("\n ======================== Creating BLE Thread for RX notifications ========================")
        ble_obj_rx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data_rx,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        time.sleep(5)
        ble_obj_rx.check_scan_functionality_dut()
        ble_obj_rx.connect_from_dut()
        ble_obj_rx.service_discovery_on_dut()

        # -------------------- TX notify thread --------------------
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        data_tx = "".join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data_tx) + 1)
        # IMPORTANT: load the payload into DUT memory (other notify_tx tests do this)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data_tx), write_content=data_tx)

        logger().info("\n ======================== Creating BLE Thread for TX notifications ========================")
        ble_obj_tx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None,
            char_uid=char_uid1,
            data=data_tx,
            service_uid=service_uid,
            data_length=240,
            data_duration=120,
            periodic_delay=0.5,
            address=address2,
            conn_interval=conn_interval,
            set_smp=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        # Create custom GATT service/characteristic on DUT (this was commented earlier)
        logger().info("Creating new custom gatt service in DUT")
        ble_obj_tx.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, service_handler_num=index, value_handler_num=index + 1
        )
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        # Make DUT advertise, let remote connect, discover, then start TX notifications
        ble_obj_tx.advertise_dut()
        ble_obj_tx.scan_and_connect_from_remote()
        ble_obj_tx.service_discovery_on_remote()

        ble_obj_rx.start()  # run() enables notifications for RX
        time.sleep(5)  # Ensure RX thread is ready before starting TX thread
        ble_obj_tx.start()

        # -------------------- WPS join (auto-connect ENABLED) --------------------
        logger().info("Starting WPS process with Auto Connect Enabled")
        wps_result = join_to_wifi_network_via_wps(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            power_save=True,
            mode='power_save_low_latency',
            ping_count=ping_count,
            retry_count=1,
            ping_after_power_save=True,
            ping_before_power_save=True,
            associated=False,
            dtim_aligned_type=0,
            num_of_dtim_skip=0,
            listen_interval=0,
            monitor_interval=0,
            ip_version="ipv4",
            tcp_ip_bypass=False,
            ip_config_disable=False,
            skip_scan=False,
            sl_collections=sl_collections
        )
        logger().info(wps_result)

        # IMPORTANT: validate before indexing into dict
        assert wps_result is not None, "WPS connection returned None"
        assert "device_ip" in wps_result and wps_result["device_ip"], f"WPS missing device_ip: {wps_result}"
        assert "dut_mac_address" in wps_result and wps_result[
            "dut_mac_address"], f"WPS missing dut_mac_address: {wps_result}"

        wifi_obj = type("obj", (object,), {
            "device_ip": wps_result["device_ip"],
            "dut_mac_address": wps_result["dut_mac_address"]
        })()

        logger().info(f"WLAN connection successful via WPS. DUT IP: {wifi_obj.device_ip}")

        # -------------------- TCP traffic --------------------
        logger().info("Starting TCP data transfer")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device IP: {host_ip}")

        sl_collections.run_traffic(
            wifi_dut=wifi_dut,
            net_perf_client=net_perf_client,
            protocol=protocol,
            device_ip=wifi_obj.device_ip,
            host_ip=host_ip,
            timeout=120,
            traffic_type="TX",
            buffer_size_tcp=1460,
            async_socket=0
        )
        logger().info("TCP data transfer successful")

        # Wait for BLE threads to finish cleanly
        ble_obj_rx.wait_for_exit()
        logger().info("BLE RX notification thread completed successfully")
        ble_obj_tx.wait_for_exit()

        logger().info("BLE TX and RX notification threads completed successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        # Cleanup
        logger().info("Cleaning up resources")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()

        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    try:
                        ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                        ble_client.interfaces.bluetooth.close()
                    except Exception:
                        pass
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_clients_address,
                                           ble_dut_address=ble_dut_address)

        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True


# Test Case 2: BLE dual role with Tx&Rx notifications while WLAN (WPS auto connect disabled) with UDP data transfer
@wifi_dut_marker(num_peripheral_connections=1, num_central_connections=1, ble_thread_count=2, ble_stack_len=3584,
                 wifi_stack_len=3584)
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913650')
def test_coex_sdk_wps_pbc_ble_dual_tx_rx_udp_auto_connect_disabled_C913650(
        wifi_dut,
        ble_clients,
        wifi_access_point,
        request,
        wifi_client,
        utf_constants,
        sl_collections,
        net_perf_client,
        protocol
):
    """
    TC2: Verify BLE dual role connections with TX & Rx notifications while WLAN (connection established via WPS)
    with auto connect disabled and UDP data transfer

    Preconditions:
        - Configure the AP with WPA2 security
        - BLE Connection Interval = 250 ms
        - Enable data transfer parameters for BLE
    """
    # global ble_obj, wifi_obj
    ble_clients_address = []
    ble_dut_address = None
    try:
        assert len(ble_clients) >= 2, "Minimum 2 Raspi devices needed"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        conn_interval = 250

        # Start BLE GATT on DUT
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)

        # -------------------- RX notify thread --------------------
        svc = "HealthThermometerService"
        charc = "CustomNotifyCharacteristic"
        data_rx = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info("\n ======================== Creating BLE Thread for RX notifications ========================")
        ble_obj_rx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data_rx,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        time.sleep(5)
        ble_obj_rx.check_scan_functionality_dut()
        ble_obj_rx.connect_from_dut()
        ble_obj_rx.service_discovery_on_dut()

        # -------------------- TX notify thread --------------------
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        data_tx = "".join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data_tx) + 1)
        # IMPORTANT: load the payload into DUT memory (other notify_tx tests do this)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data_tx), write_content=data_tx)

        logger().info("\n ======================== Creating BLE Thread for TX notifications ========================")
        ble_obj_tx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None,
            char_uid=char_uid1,
            data=data_tx,
            service_uid=service_uid,
            data_length=240,
            data_duration=120,
            periodic_delay=0.5,
            address=address2,
            conn_interval=conn_interval,
            set_smp=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        time.sleep(5)

        # Create custom GATT service/characteristic on DUT (this was commented earlier)
        logger().info("Creating new custom gatt service in DUT")
        ble_obj_tx.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, service_handler_num=index, value_handler_num=index + 1
        )
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        # Make DUT advertise, let remote connect, discover, then start TX notifications
        ble_obj_tx.advertise_dut()
        ble_obj_tx.scan_and_connect_from_remote()
        ble_obj_tx.service_discovery_on_remote()

        ble_obj_rx.start()  # run() enables notifications for RX
        time.sleep(5)  # Ensure RX thread is ready before starting TX thread
        ble_obj_tx.start()

        # -------------------- WPS join (auto-connect DISABLED) --------------------
        logger().info("Starting WPS PBC with auto_connect disabled")

        logger().info("Enabling WPS PBC on Access Point")
        wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
        time.sleep(2)

        wps_response = wifi_dut.interfaces.wifi.start_client_wps(auto_connect=False)

        assert wps_response is not None, "WPS response is NULL"
        logger().info(f"WPS response: {wps_response}")

        # ------------------ Manual Join After WPS ------------------
        logger().info("Manually joining AP after WPS")

        wps_join = wifi_dut.interfaces.wifi.join(
            ssid=wifi_access_point.interfaces.wifi.ssid,
            passphrase=wifi_access_point.interfaces.wifi.passphrase,
            security=wifi_access_point.interfaces.wifi.security.name.lower(),
            timeout=60
        )

        logger().info(f"Manual join result: {wps_join}")

        # ------------------ Configure IP ------------------
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=3)
        assert ip_status, "Failed to obtain IP address via DHCP"

        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP Address: {device_ip}")

        # -------------------- TCP traffic --------------------
        logger().info("Starting UDP data transfer")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device IP: {host_ip}")

        sl_collections.run_traffic(
            wifi_dut=wifi_dut,
            net_perf_client=net_perf_client,
            protocol=protocol,
            device_ip=device_ip,
            host_ip=host_ip,
            timeout=120,
            traffic_type="RX",
            buffer_size_tcp=1460,
            async_socket=0
        )
        logger().info("UDP data transfer successful")

        # Wait for BLE threads to finish cleanly
        ble_obj_rx.wait_for_exit()
        ble_obj_tx.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        # Cleanup
        logger().info("Cleaning up resources")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()

        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    try:
                        ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                        ble_client.interfaces.bluetooth.close()
                    except Exception:
                        pass
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_clients_address,
                                           ble_dut_address=ble_dut_address)

        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True


@wifi_dut_marker()
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913651')
def test_coex_sdk_wps_pbc_ble_central_rx_http_auto_connect_enabled_C913651(
        wifi_dut,
        ble_client,
        wifi_access_point,
        request,
        utf_constants,
        sl_collections,
        http_server,
        index_path,
):
    """
    Verify WLAN (connection established via WPS) with auto connect enabled and HTTP download
    when BLE is connected as a central and Rx notifications

    Preconditions:
        - Configure the AP with WPA2 security
        - BLE Connection Interval = 250 ms
        - Enable data transfer parameters for BLE
    """
    global ble_obj, wifi_obj

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        conn_interval = 250

        # Initiate WLAN connection using WPS with auto connect enabled
        logger().info("Initiating WLAN connection using WPS with auto connect enabled")
        wps_result = join_to_wifi_network_via_wps(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            power_save=True,
            mode='power_save_low_latency',
            ping_count=10,
            retry_count=1,
            ping_after_power_save=True,
            ping_before_power_save=True,
            associated=False,
            dtim_aligned_type=0,
            num_of_dtim_skip=0,
            listen_interval=0,
            monitor_interval=0,
            ip_version='ipv4',
            tcp_ip_bypass=False,
            ip_config_disable=False,
            skip_scan=False,
            sl_collections=sl_collections
        )
        assert wps_result is not None and 'device_ip' in wps_result, "WPS connection failed"
        wifi_obj = type('obj', (object,), {'device_ip': wps_result['device_ip']})()

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        # -------------------- RX notify thread --------------------
        svc = "HealthThermometerService"
        charc = "CustomNotifyCharacteristic"
        data_rx = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info("\n ======================== Creating BLE Thread for RX notifications ========================")
        ble_obj_rx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data_rx,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        time.sleep(5)
        ble_obj_rx.check_scan_functionality_dut()
        ble_obj_rx.connect_from_dut()
        ble_obj_rx.service_discovery_on_dut()

        ble_obj_rx.start()

        # Step 9: Initiate HTTP download
        logger().info("Initiating HTTP download")
        sl_collections.http_file_download(
            wifi_dut=wifi_dut,
            http_server=http_server,
            index_path=index_path,
            device_ip=wifi_obj.device_ip,
            https=0
        )
        logger().info("HTTP download successful")

        # Step 10: Monitor WLAN activity during BLE central connection
        logger().info("Monitoring WLAN activity during BLE central connection")
        time.sleep(30)
        assert wifi_dut.interfaces.wifi.associated, "WLAN connection lost"
        logger().info("WLAN HTTP download remains unaffected by BLE central connection")

        ble_obj_rx.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

        http_server.interfaces.http.stop_server()


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 ble_stack_len=3584,
                 ble_thread_count=2,
                 wifi_stack_len=3584,
                 wifi_thread_count=1,
                 num_peripheral_connections=1,
                 num_central_connections=1)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913652')
def test_coex_sdk_wps_pbc_ble_dual_role_tx_rx_https_auto_connect_disabled_C913652(
        wifi_dut,
        ble_clients,
        wifi_access_point,
        request,
        utf_constants,
        sl_collections,
        http_server,
        index_path,
):
    """
    Verify WLAN (connection established via WPS) with auto connect enabled and HTTP download
    when BLE is connected as a central and Rx notifications

    Preconditions:
        - Configure the AP with WPA2 security
        - BLE Connection Interval = 250 ms
        - Enable data transfer parameters for BLE
    """
    ble_clients_address = []
    ble_dut_address = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        conn_interval = 250

        # Initiate WLAN connection using WPS with auto connect enabled
        logger().info("Initiating WLAN connection using WPS with auto connect enabled")
        wps_result = join_to_wifi_network_via_wps(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            power_save=True,
            mode='power_save_low_latency',
            ping_count=10,
            retry_count=1,
            ping_after_power_save=True,
            ping_before_power_save=True,
            associated=False,
            dtim_aligned_type=0,
            num_of_dtim_skip=0,
            listen_interval=0,
            monitor_interval=0,
            ip_version='ipv4',
            tcp_ip_bypass=False,
            ip_config_disable=False,
            skip_scan=False,
            sl_collections=sl_collections
        )
        assert wps_result is not None and 'device_ip' in wps_result, "WPS connection failed"
        wifi_obj = type('obj', (object,), {'device_ip': wps_result['device_ip']})()

        # Start BLE GATT on DUT
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        # -------------------- RX notify thread --------------------
        svc = "HealthThermometerService"
        charc = "CustomNotifyCharacteristic"
        data_rx = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info("\n ======================== Creating BLE Thread for RX notifications ========================")
        ble_obj_rx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data_rx,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        time.sleep(5)
        ble_obj_rx.check_scan_functionality_dut()
        ble_obj_rx.connect_from_dut()
        ble_obj_rx.service_discovery_on_dut()

        # -------------------- TX notify thread --------------------
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        data_tx = "".join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data_tx) + 1)
        # IMPORTANT: load the payload into DUT memory (other notify_tx tests do this)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data_tx), write_content=data_tx)

        logger().info("\n ======================== Creating BLE Thread for TX notifications ========================")
        ble_obj_tx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None,
            char_uid=char_uid1,
            data=data_tx,
            service_uid=service_uid,
            data_length=240,
            data_duration=120,
            periodic_delay=1.0,
            address=address2,
            conn_interval=conn_interval,
            set_smp=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        time.sleep(5)

        # Create custom GATT service/characteristic on DUT (this was commented earlier)
        logger().info("Creating new custom gatt service in DUT")
        ble_obj_tx.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, service_handler_num=index, value_handler_num=index + 1
        )
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        # Make DUT advertise, let remote connect, discover, then start TX notifications
        ble_obj_tx.advertise_dut()
        ble_obj_tx.scan_and_connect_from_remote()
        ble_obj_tx.service_discovery_on_remote()

        ble_obj_rx.start()  # run() enables notifications for RX
        time.sleep(5)  # Ensure RX thread is ready before starting TX thread
        ble_obj_tx.start()

        # Step 9: Initiate HTTP download
        logger().info("Initiating HTTPS download")
        sl_collections.http_file_download(
            wifi_dut=wifi_dut,
            http_server=http_server,
            index_path=index_path,
            device_ip=wifi_obj.device_ip,
            https=1
        )
        logger().info("HTTPS download successful")

        # Step 10: Monitor WLAN activity during BLE central connection
        logger().info("Monitoring WLAN activity during BLE central connection")
        time.sleep(30)
        assert wifi_dut.interfaces.wifi.associated, "WLAN connection lost"
        logger().info("WLAN HTTPS download remains unaffected by BLE central connection")

        ble_obj_rx.wait_for_exit()
        ble_obj_tx.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        # Cleanup
        logger().info("Cleaning up resources")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()

        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    try:
                        ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                        ble_client.interfaces.bluetooth.close()
                    except Exception:
                        pass
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_clients_address,
                                           ble_dut_address=ble_dut_address)

        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DHCPv6Client
                              | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                              | Si91xTCPIPFeatureBitMap.IPv6Mode
                              | Si91xTCPIPFeatureBitMap.DHCPv6Server
                              | Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 ble_stack_len=3584,
                 ble_thread_count=1,
                 wifi_stack_len=3584,
                 wifi_thread_count=1,
                 num_peripheral_connections=1)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "ipv6_state": "1"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913655')
def test_coex_sdk_wps_pbc_ipv6_stateful_ble_peripheral_tx_https_auto_connect_enabled_C913655(
        wifi_dut,
        ble_client,
        wifi_access_point,
        request,
        utf_constants,
        sl_collections,
        http_server,
        index_path,
        wifi_client
):
    """
    Verify WLAN+stateful DHCPv6 (connection established via WPS) with auto connect enabled
    and HTTPS download when BLE is connected as a peripheral and Tx notifications

    Preconditions:
        - Configure the AP with WPA2 security
        - Enable IPv6 in the AP and set the mode to stateful
        - BLE Connection Interval = 30ms
        - Enable data transfer parameters for BLE
    """
    global ble_obj, wifi_obj
    ble_dut_address = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        conn_interval = 250

        wps_result = join_to_wifi_network_via_wps(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, power_save=True,
                                     mode='power_save_low_latency', channel=0,
                                     ping_count=ping_count, retry_count=1, ping_after_power_save=True,
                                     ping_before_power_save=True,
                                     associated=False,
                                     dtim_aligned_type=0, num_of_dtim_skip=0, listen_interval=0, monitor_interval=0,
                                     ip_version='ipv6', tcp_ip_bypass=False, ip_config_disable=False,
                                     ipv6_type='global', skip_scan=False, sl_collections=sl_collections)

        logger().info(f"WPS connection result: {wps_result}")
        device_ip = wps_result["device_ip"]
        logger().info(f"DUT IPv6 Address obtained via WPS: {device_ip}")

        # Start BLE GATT on DUT
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        # -------------------- TX notify thread --------------------
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        data_tx = "".join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data_tx) + 1)
        # IMPORTANT: load the payload into DUT memory (other notify_tx tests do this)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data_tx), write_content=data_tx)

        logger().info("\n ======================== Creating BLE Thread for TX notifications ========================")
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None,
            char_uid=char_uid1,
            data=data_tx,
            service_uid=service_uid,
            data_length=240,
            data_duration=120,
            periodic_delay=1,
            address=address2,
            conn_interval=conn_interval,
            set_smp=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        # Create custom GATT service/characteristic on DUT (this was commented earlier)
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, service_handler_num=index, value_handler_num=index + 1
        )
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        # Make DUT advertise, let remote connect, discover, then start TX notifications
        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_remote()

        time.sleep(5)  # Ensure RX thread is ready before starting TX thread
        ble_obj.start()

        logger().info("Starting HTTPS download")

        http_obj = HttpDownload(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, test_name=test_name,
            wifi_client=wifi_client, device_ip=device_ip, ip_version=6, http_server=http_server,
            index_path=index_path, ipv6_addr_type="global", https=1
        )

        http_obj.start()
        http_obj.wait_for_exit()
        time.sleep(5)  # Ensure any final BLE notifications are sent after HTTP download completes

        ble_obj.wait_for_exit()

        logger().info("BLE TX notification thread and HTTP download thread completed successfully")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("Cleaning up resources")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()

        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DHCPv6Client
                              | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                              | Si91xTCPIPFeatureBitMap.IPv6Mode
                              | Si91xTCPIPFeatureBitMap.DHCPv6Server
                              | Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 ble_stack_len=3584,
                 ble_thread_count=2,
                 wifi_stack_len=3584,
                 wifi_thread_count=1,
                 num_peripheral_connections=1)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "ipv6_state": "0"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913656')
def test_coex_sdk_wps_pbc_ipv6_stateless_ble_dual_tx_rx_https_auto_connect_disabled_C913656(
        wifi_dut,
        ble_clients,
        wifi_access_point,
        request,
        utf_constants,
        sl_collections,
        http_server,
        index_path,
        wifi_client
):
    """
    Verify WLAN+stateful DHCPv6 (connection established via WPS) with auto connect enabled
    and HTTPS download when BLE is connected as a peripheral and Tx notifications

    Preconditions:
        - Configure the AP with WPA2 security
        - Enable IPv6 in the AP and set the mode to stateful
        - BLE Connection Interval = 30ms
        - Enable data transfer parameters for BLE
    """
    global ble_obj, wifi_obj
    ble_clients_address = []
    ble_dut_address = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        conn_interval = 250

        # Start BLE GATT on DUT
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        # -------------------- RX notify thread --------------------
        svc = "HealthThermometerService"
        charc = "CustomNotifyCharacteristic"
        data_rx = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info("\n ======================== Creating BLE Thread for RX notifications ========================")
        ble_obj_rx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data_rx,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        time.sleep(5)
        ble_obj_rx.check_scan_functionality_dut()
        ble_obj_rx.connect_from_dut()
        ble_obj_rx.service_discovery_on_dut()

        # -------------------- TX notify thread --------------------
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        data_tx = "".join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data_tx) + 1)
        # IMPORTANT: load the payload into DUT memory (other notify_tx tests do this)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data_tx), write_content=data_tx)

        logger().info("\n ======================== Creating BLE Thread for TX notifications ========================")
        ble_obj_tx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None,
            char_uid=char_uid1,
            data=data_tx,
            service_uid=service_uid,
            data_length=240,
            data_duration=120,
            periodic_delay=0.5,
            address=address2,
            conn_interval=conn_interval,
            set_smp=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        # Create custom GATT service/characteristic on DUT (this was commented earlier)
        logger().info("Creating new custom gatt service in DUT")
        ble_obj_tx.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(
            uid=0x1AA1, service_handler_num=index, value_handler_num=index + 1
        )
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        # Make DUT advertise, let remote connect, discover, then start TX notifications
        ble_obj_tx.advertise_dut()
        ble_obj_tx.scan_and_connect_from_remote()
        ble_obj_tx.service_discovery_on_remote()

        ble_obj_rx.start()  # run() enables notifications for RX
        time.sleep(5)  # Ensure RX thread is ready before starting TX thread
        ble_obj_tx.start()

        # -------------------- WPS join (auto-connect DISABLED) --------------------
        logger().info("Starting WPS PBC with auto_connect disabled")

        logger().info("Enabling WPS PBC on Access Point")
        wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
        time.sleep(2)

        wps_response = wifi_dut.interfaces.wifi.start_client_wps(auto_connect=False)

        assert wps_response is not None, "WPS response is NULL"
        logger().info(f"WPS response: {wps_response}")

        # ------------------ Manual Join After WPS ------------------
        logger().info("Manually joining AP after WPS")

        wps_join = wifi_dut.interfaces.wifi.join(
            ssid=wifi_access_point.interfaces.wifi.ssid,
            passphrase=wifi_access_point.interfaces.wifi.passphrase,
            security=wifi_access_point.interfaces.wifi.security.name.lower(),
            timeout=60
        )

        logger().info(f"Manual join result: {wps_join}")
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=1, ip_version="ipv6")
        assert ip_status, "Failed to obtain global IPv6 address via DHCP"

        device_ip = ip_config[1]
        logger().info(f"DUT IP Address: {device_ip}")

        logger().info("Starting HTTPS download")

        http_obj = HttpDownload(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                test_name=test_name, wifi_client=wifi_client,
                                device_ip=device_ip,
                                ip_version=6, http_server=http_server, index_path=index_path,
                                ipv6_addr_type="global", https=1)


        http_obj.start()
        http_obj.wait_for_exit()
        logger().info("HTTPS download successful")

        logger().info("Monitoring WLAN activity during BLE peripheral connection")
        time.sleep(30)
        assert wifi_dut.interfaces.wifi.associated, "WLAN connection lost"
        logger().info("WLAN HTTPS download remains unaffected by BLE peripheral connection")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("Cleaning up resources")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()

        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    try:
                        ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                        ble_client.interfaces.bluetooth.close()
                    except Exception:
                        pass
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_clients_address,
                                           ble_dut_address=ble_dut_address)

        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True

@wifi_dut_marker(num_peripheral_connections=1, num_central_connections=1, ble_thread_count=1, ble_stack_len=2048,
                 wifi_stack_len=3584)
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913665')
def test_coex_sdk_wps_pbc_timeout_ble_peripheral_tx_C913665(
        wifi_dut,
        ble_client,
        wifi_access_point,
        request,
        utf_constants,
        sl_collections,
):
    """
    TC11: Verify WPS PBC auto-connect timeout behavior when BLE DUT operates as a peripheral with Tx notifications

    Preconditions:
        - Configure the AP with WPA2 security
        - BLE Connection Interval = 250 ms
        - Enable data transfer parameters for BLE
        - Initiate BLE connection with SMP
    """
    global ble_obj
    ble_obj = None

    try:
        test_name = request.node.name
        conn_interval = 250

        # -------------------- BLE Initialization (Peripheral, TX, SMP) --------------------
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1

        # Allocate and load data for TX notification
        address = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)

        logger().info("Initializing BLE Thread (Peripheral, TX, SMP Enabled)...")
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,  # Requirement: SMP/Pairing
            bond_info=1,
            char_path=None, char_uid=char_uid, data=data,
            service_uid=service_uid,
            data_length=240, data_duration=120,
            periodic_delay=0.5,
            address=address,
            conn_interval=conn_interval,
            set_smp=1  # Requirement: SMP Enabled
        )

        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        # Start BLE: Advertise -> Connect -> Discovery -> Start Notifications
        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_remote()
        ble_obj.start()

        logger().info("BLE Connection Established and Traffic Started.")

        # -------------------- WPS PBC Timeout Logic --------------------
        # To test timeout, we enable WPS on DUT but NOT on the AP.
        logger().info("Starting WPS PBC on DUT (Expecting Timeout after ~120s)...")
        logger().info("Note: AP WPS is intentionally NOT triggered to force timeout condition.")

        start_time = time.time()
        timeout_limit = 130  # Allow buffer over standard 120s

        try:
            # We call start_client_wps directly. Depending on implementation, this may block
            # until success/timeout or return immediately.
            wifi_dut.interfaces.wifi.start_client_wps(
                interface="client",
                wps_role=0,  # Enrollee
                wps_mode=0,  # PBC
                auto_connect=True
            )

            # If the call returns immediately, we poll for association or failure
            logger().info("WPS command issued. Monitoring DUT state for timeout...")
            while time.time() - start_time < timeout_limit:
                if wifi_dut.interfaces.wifi.associated:
                    assert False, "Test Failure: DUT associated with AP! (Expected Timeout)"
                time.sleep(5)
                logger().info(f"Waiting for timeout... Elapsed: {int(time.time() - start_time)}s")

        except Exception as e:
            # Check if exemption is due to timeout/failure (Expected)
            err_msg = str(e).lower()
            logger().info(f"Received Exception during WPS wait: {err_msg}")

        # -------------------- Verification --------------------

        # 1. Verify DUT is NOT associated
        assert not wifi_dut.interfaces.wifi.associated, "DUT should not be associated after WPS timeout period"
        logger().info("Success: DUT correctly exited WPS mode without association.")

        # 2. Verify BLE is still connected/active
        # Simple check: verify the internal state or that the thread didn't crash
        try:
            # Get BLE device state (Expected: Connected/8)
            ble_state = wifi_dut.interfaces.wifi.ble_get_device_state()
            logger().info(f"BLE Device State after WPS Timeout: {ble_state}")
            # Depending on mapping, 8 is usually connected
            # If the command fails, it indicates BLE stack crash
        except Exception as e:
            assert False, f"BLE Stack unresponsive after WPS Timeout: {e}"

        ble_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("Cleaning up resources")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()

        if ble_obj:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                           ble_client_address=ble_obj.ble_client_address,
                                           ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(num_peripheral_connections=0, num_central_connections=1,
                 ble_thread_count=1, ble_stack_len=3584, wifi_stack_len=3584)
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913667')
def test_coex_sdk_wps_pbc_connection_reconnection_ble_central_tx_indications_C913667(
wifi_dut, ble_client, wifi_access_point, request, utf_constants, sl_collections, ):
    """
    Verify repeated WPS PBC connect–disconnect cycles while BLE central TX indications remain stable.
    """

    ble_obj = None
    ble_dut_address = None
    ping_count = 10
    iterations = 5

    try:
        # -------------------------------------------------------------
        # Step 1-3: Initial WPS PBC connection (auto connect enabled)
        # -------------------------------------------------------------
        logger().info("Initiating initial WPS PBC connection")

        wps_result = join_to_wifi_network_via_wps(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            power_save=True,
            ping_count=ping_count,
            associated=False,
            sl_collections=sl_collections
        )

        assert wps_result and "device_ip" in wps_result, "Initial WPS connection failed"

        device_ip = wps_result["device_ip"]

        # -------------------------------------------------------------
        # Step 4–7: Advertise remote, scan, connect with SMP
        # -------------------------------------------------------------

        # Ensure DUT bluetooth interface alias exists
        ble_obj_ind = IndicationThread(
            wifi_dut=wifi_dut, ble_client=ble_client
        )

        ble_obj_ind.start()
        logger().info("Waiting for BLE central connection to be established")
        ble_obj_ind.ble_ready_event.wait(timeout=180)
        logger().info("BLE central connection established successfully")

        # -------------------------------------------------------------
        # Step 8–11: Repeat connect–disconnect WPS cycles
        # -------------------------------------------------------------
        for i in range(iterations):
            logger().info(f"--- WPS Reconnect Cycle {i + 1} ---")

            # Step 9: Disconnect WLAN
            logger().info("Disconnecting WLAN")
            wifi_dut.interfaces.wifi.leave()
            time.sleep(3)
            assert not wifi_dut.interfaces.wifi.associated, "WLAN disconnection failed"

            wps_result = join_to_wifi_network_via_wps(
                wifi_dut=wifi_dut,
                wifi_access_point=wifi_access_point,
                power_save=True,
                ping_count=ping_count,
                associated=False,
                sl_collections=sl_collections,
                ping_after_power_save=False,
                ping_before_power_save=False,
            )

            assert wps_result and "device_ip" in wps_result, \
                f"WPS reconnection failed in iteration {i + 1}"

            device_ip = wps_result["device_ip"]

            # Validate ping after reconnection
            assert sl_collections.ping(device_ip=device_ip, ping_count=10), \
                f"Ping failed after reconnection in iteration {i + 1}"

            logger().info(f"WPS cycle {i + 1} completed successfully")

        assert wifi_dut.interfaces.wifi.ble_get_device_state(), "BLE connection lost at end of test"

        logger().info("All WPS connect–disconnect cycles completed successfully")
        ble_obj_ind.stop()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Cleaning up resources")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            ble_obj.clear_dut(role="master")

# Skip
@pytest.mark.skip(reason="Is in the file - test_sta_ble_provisioning_2ap_sdk.py as there is a dependency of the setup (2APs)")
@pytest.mark.test_src_map_id('C913668')
def test_wps_pbc_lockout_with_ble_coex_C913668():
        pass

@wifi_dut_marker()
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913669')
def test_coex_sdk_wps_pbc_ap_reboot_ble_peripheral_tx_C913669(
        switch,
        wifi_dut,
        ble_client,
        wifi_access_point,
        request,
        utf_constants,
        sl_collections,
):
    """
    TC15: Verify STA behavior during AP reboot within WPS PBC timeout with auto connect enabled
    when DUT BLE is connected as peripheral with Tx notifications

    Preconditions:
        - Configure the AP with WPS and with WPA2 security
        - BLE connection Interval = 30ms
        - Enable BLE data transfer parameters
    """
    global ble_obj, wifi_obj
    try:
        conn_interval = 250
        # ---------------------------------------------------------
        # Step 1: Initiate WPS (auto connect enabled)
        # ---------------------------------------------------------
        logger().info("Initiating WPS PBC (auto connect enabled)")
        wps_start_time = time.time()

        wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
        time.sleep(2)

        wifi_dut.interfaces.wifi.start_client_wps(
            interface="client",
            wps_role=0,
            wps_mode=0,
            auto_connect=True
        )

        # Wait for association within 120 seconds
        deadline = wps_start_time + 120
        while time.time() < deadline:
            if wifi_dut.interfaces.wifi.associated:
                break
            time.sleep(1)

        assert wifi_dut.interfaces.wifi.associated, \
            "WPS auto-connect did not associate within 120 seconds"

        wps_connected_time = time.time()
        logger().info("WPS connection established successfully")

        # ---------------------------------------------------------
        # Step 2: DHCP + Ping validation
        # ---------------------------------------------------------
        ip_status, ip_config = sl_collections.configure_ip(
            wifi_dut,
            ip_status=False,
            retry_count=3,
            ip_version="ipv4"
        )
        assert ip_status, f"DHCP failed: {ip_config}"

        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        assert sl_collections.ping(device_ip=device_ip, ping_count=10), \
            "Ping failed after WPS association"

        # ---------------------------------------------------------
        # Step 3: Initialize BLE + Connection
        # ---------------------------------------------------------
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert ble_dut_address, "BLE initialization failed"

        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1
        address = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None, char_uid=char_uid, data=data,
            service_uid=service_uid,
            data_length=240, data_duration=120,
            periodic_delay=0.5,
            address=address,
            conn_interval=conn_interval,
            set_smp=1
        )

        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_remote()
        ble_obj.start()

        # ---------------------------------------------------------
        # Step 4: Reboot AP within 120 seconds of WPS connection
        # ---------------------------------------------------------
        elapsed_since_wps = time.time() - wps_connected_time

        assert elapsed_since_wps < 120, \
            "Exceeded 120-second window before AP reboot"

        logger().info("Rebooting AP within 120 seconds of WPS connection")

        switch.interfaces.pdu_switch.turn_off(delay=10)
        switch.interfaces.pdu_switch.turn_on(delay=60)

        # ---------------------------------------------------------
        # Step 5: Monitor BLE stability + WiFi reconnection
        # ---------------------------------------------------------
        time.sleep(20)

        # Verify BLE still connected
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, \
            "BLE connection lost during AP reboot"

        logger().info("BLE connection remained stable during AP reboot")

        # Wait for WiFi reconnection
        reconnect_deadline = time.time() + 90
        while time.time() < reconnect_deadline:
            if wifi_dut.interfaces.wifi.associated:
                break
            time.sleep(2)

        assert wifi_dut.interfaces.wifi.associated, \
            "DUT did not reconnect to WiFi after AP reboot"

        assert sl_collections.ping(device_ip=device_ip, ping_count=10), \
            "Ping failed after WiFi reconnection"

        logger().info("WiFi reconnection verified successfully")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker()
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C913670')
def test_coex_sdk_wps_pbc_ap_rejoin_ble_central_rx_C913670(
        switch,
        wifi_dut,
        ble_client,
        wifi_access_point,
        request,
        utf_constants,
        sl_collections,
):
    """
    TC15: Verify STA behavior during AP reboot within WPS PBC timeout with auto connect enabled
    when DUT BLE is connected as peripheral with Tx notifications

    Preconditions:
        - Configure the AP with WPS and with WPA2 security
        - BLE connection Interval = 30ms
        - Enable BLE data transfer parameters
    """
    global ble_obj, wifi_obj

    try:
        ping_count = utf_constants.get("ping_count")
        conn_interval = 250

        # Step 1: Initiate WLAN connection using WPS with auto connect enabled
        logger().info(" Initiating WLAN connection using WPS with auto connect enabled")
        wps_result = join_to_wifi_network_via_wps(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            power_save=True,
            mode='power_save_low_latency',
            ping_count=ping_count,
            retry_count=1,
            ping_after_power_save=True,
            ping_before_power_save=True,
            associated=False,
            dtim_aligned_type=0,
            num_of_dtim_skip=0,
            listen_interval=0,
            monitor_interval=0,
            ip_version='ipv4',
            tcp_ip_bypass=False,
            ip_config_disable=False,
            ipv6_type='global',
            skip_scan=False,
            sl_collections=sl_collections
        )
        assert wps_result is not None and 'device_ip' in wps_result, "WPS connection failed"
        wifi_obj = type('obj', (object,), {'device_ip': wps_result['device_ip']})()

        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        # Create BleThread for Rx notifications - ble_connect() handles connection, start() handles notifications
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data,
            conn_interval=conn_interval
        )

        # Connect as master - ble_connect() handles advertise, scan, connect
        ble_obj.ble_connect()

        ble_obj.service_discovery_on_dut()  # Discover services

        # Start thread - this calls run() which calls enable_notifications_remote()
        ble_obj.start()

        # Reboot the AP after 120 seconds of WPS connection
        logger().info(" Rebooting AP after 120 seconds of WPS connection")
        time.sleep(120)  # Wait 120 seconds after connection

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)

        logger().info("Monitoring BLE data flow and Wi-Fi reconnection")

        # Verify BLE connection remains stable during AP reboot
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost during AP reboot"
        logger().info("BLE connection remained stable during AP reboot")

        # Wait for Wi-Fi reconnection (should reconnect automatically with stored credentials)
        logger().info("Waiting for Wi-Fi reconnection after AP reboot")
        max_wait_reconnect = 60
        elapsed_reconnect = 0
        while elapsed_reconnect < max_wait_reconnect:
            if wifi_dut.interfaces.wifi.associated:
                logger().info("Wi-Fi reconnected successfully after AP reboot")
                break
            time.sleep(2)
            elapsed_reconnect += 2

        assert wifi_dut.interfaces.wifi.associated, "Wi-Fi did not reconnect after AP reboot"

        ping_status = sl_collections.ping(device_ip=wifi_obj.device_ip, ping_count=10)
        assert ping_status, "Ping failed after reconnection"
        logger().info("Wi-Fi reconnection and connectivity verified successfully")
        ble_obj.wait_for_exit()

    except Exception as e:
        logger().error(f"Test failed: {str(e)}")
        raise
    finally:
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)