import re
import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs

"""
Setup Requirements:
    - DUT(917-SDK)
    - EFR32
    - Raspberry PI4

Author:
    - Achal Raghav
"""


def logger():
    return get_logger(__name__)


class BLEThread(ThreadBase):
    # Class Attributes for BLE address variations
    ble_adv_data = 'BLE_ADDRESS_VARIATIONS'
    ble_public_address = None
    ble_private_address = "26:28:F0:47:28:79"
    ble_address_resolution_timeout = 1

    addr_type = {
        0 : 'LE_PUBLIC_ADDRESS',
        1 : 'LE_RANDOM_ADDRESS',
        2 : 'LE_RESOLVABLE_PUBLIC_ADDRESS',
        3 : 'LE_RESOLVABLE_RANDOM_ADDRESS'
    }

    # Initialization method
    def __init__(self, ble_dut=None, ble_client=None, testcase_id=None, bt_mon_log_file_name=None, power_save_enable=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_client = ble_client
        self.testcase_id = testcase_id
        self.bt_mon_log_file_name = bt_mon_log_file_name
        self.power_save_enable = power_save_enable

    def run(self):
        BLEThread.ble_public_address = self.ble_dut.interfaces.wifi.ble_start(set_smp=1)
        assert self.ble_public_address is not None, "Failed to start BLE"

        if self.testcase_id == 485433:
            self.testcase_485433()
        if self.testcase_id == 485438:
            self.testcase_485438()
        if self.testcase_id == 485439:
            self.testcase_485439()
        if self.testcase_id == 478666:
            self.testcase_478666()
        if self.testcase_id == 478667:
            self.testcase_478667()
        if self.testcase_id == 477084:
            self.testcase_477084()

    # Testcase 485433: Verify advertising start/stop using public/random addresses
    def testcase_485433(self):
        records = self.advertise_dut_using_address(BLEThread.ble_public_address, "Public", 0, ["UNDIR_CONN", 128])
        self.validate_address(records, BLEThread.ble_public_address, "Public")
        self.ble_client.interfaces.bluetooth.close()
        logger().info(f"Setting BLE address to random LE address: {BLEThread.ble_private_address}...")
        self.ble_dut.interfaces.wifi.set_ble_address(ble_address=BLEThread.ble_private_address)
        records = self.advertise_dut_using_address(BLEThread.ble_private_address, "Random", 1, ["UNDIR_CONN", 128])
        self.validate_address(records, BLEThread.ble_private_address, "Random")

    # Testcase 485438: Verify advertisement types with resolvable private address and different advertisement types
    # and intervals
    def testcase_485438(self):
        logger().info(f"Setting BLE address to random LE address: {BLEThread.ble_private_address}...")
        self.ble_dut.interfaces.wifi.set_ble_address(ble_address=BLEThread.ble_private_address)
        ble_adv_types = {
            "UNDIR_CONN": 128,
            "UNDIR_SCAN": 130,
            "UNDIR_NON_CONN": 131
        }
        btmon_advertisement_types = ['Connectable undirected - ADV_IND (0x00)',
                                     'Scannable undirected - ADV_SCAN_IND (0x02)',
                                     'Non connectable undirected - ADV_NONCONN_IND (0x03)']
        for index, ble_adv_type in enumerate(ble_adv_types):
            with BleLogs(
                    start_collecting_logs=True,
                    bt_log_path=self.bt_mon_log_file_name,
            ) as bt_logs:
                logger().info(f"BLE starts advertisement with {ble_adv_type}, min interval: 32ms, max interval: 160ms...")
                self.ble_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=BLEThread.ble_adv_data,
                                                                   ble_adv_type=ble_adv_types[ble_adv_type],
                                                                   own_addr_type=3, ble_adv_int_min=32,
                                                                   ble_adv_int_max=160)
                if self.power_save_enable:
                    self.power_save_enable = False
                    self.power_save()
                self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=BLEThread.ble_private_address)
                time.sleep(5)
                self.ble_client.interfaces.bluetooth.stop_scanning()
                self.ble_dut.interfaces.wifi.ble_stop_advertising()
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                assert len(found_devices) > 0, "No devices found"
                logger().info("Found devices: {}".format(found_devices))
                self.ble_client.interfaces.bluetooth.close()
                records = self.fetch_data_from_btmon_logs(bt_mon_log_file_name=self.bt_mon_log_file_name)
                found_desired_record = ()
                for item in records:
                    if BLEThread.ble_private_address in item:
                        found_desired_record = item
                        break
                # Apply the assertion block for address type
                assert found_desired_record[
                           1] == btmon_advertisement_types[
                           index], f"Advertisement type doesn't match for : {BLEThread.ble_private_address}"

    def testcase_485439(self):
        logger().info(f"....Adding device {BLEThread.ble_public_address} into BLE Resolve list")
        self.ble_dut.interfaces.wifi.ble_resolvelist(process_type=1, remote_addr_type=0,
                                                     ble_device_address=BLEThread.ble_public_address)
        with BleLogs(
                start_collecting_logs=True,
                bt_log_path=self.bt_mon_log_file_name
        ) as bt_logs:
            logger().info(f"....Enabling the Address Resolution with timeout 5 seconds....")
            self.ble_dut.interfaces.wifi.ble_set_address_resolution_enable(address_resolution_enable=1,
                                                                           address_resolution_timeout=BLEThread.ble_address_resolution_timeout)
            logger().info(f"....BLE starts Advertisement with {BLEThread.addr_type[2]}")
            self.ble_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=BLEThread.ble_adv_data, own_addr_type=2, ble_adv_int_min=32,
                                                                   ble_adv_int_max=160)
            self.power_save()
            logger().info("....Remote device starts Scanning....")
            self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=BLEThread.ble_public_address)
            time.sleep(15)
            logger().info("....Stopping BLE Scan....")
            self.ble_client.interfaces.bluetooth.stop_scanning()
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert len(found_devices) > 0, "No devices found"
            logger().info("\nScanned devices: {}\n".format(found_devices))
            logger().info(f"....Fetching Data from BTMon Logs....")
            records = self.fetch_data_from_btmon_logs(self.bt_mon_log_file_name)
            resolved_addresses = set()
            for record in records:
                if BLEThread.ble_adv_data in record:
                    assert record[2] == 'Random', "....The Resolved address isn't Random...."
                    assert record[4] == 'Resolvable', "....The address type isn't Resolvable...."
                    resolved_addresses.add(record[3])
            logger().info(f"The Resolved addresses with advertisisng data {BLEThread.ble_adv_data} are {resolved_addresses}")
            assert BLEThread.ble_public_address not in resolved_addresses, "\n\n....ADDRESS ISN'T RESOLVED....\n\n"
            self.ble_dut.interfaces.wifi.ble_stop_advertising()
            logger().info("....DISABLING THE BLE ADDRESS RESOLUTION....")
            self.ble_dut.interfaces.wifi.ble_set_address_resolution_enable(address_resolution_enable=0)

    def testcase_477084(self):
        logger().info(f"....Adding device {BLEThread.ble_public_address} into BLE Resolve list")
        self.ble_dut.interfaces.wifi.ble_resolvelist(process_type=1, remote_addr_type=0,
                                                     ble_device_address=BLEThread.ble_public_address)
        with BleLogs(
                start_collecting_logs=True,
                bt_log_path=self.bt_mon_log_file_name
        ) as bt_logs:
            logger().info(f"....Enabling the Address Resolution with timeout {BLEThread.ble_address_resolution_timeout} seconds....")
            self.ble_dut.interfaces.wifi.ble_set_address_resolution_enable(address_resolution_enable=1,
                                                                           address_resolution_timeout=BLEThread.ble_address_resolution_timeout)
            logger().info(f"....BLE starts Advertisement with {BLEThread.addr_type[2]}")
            self.ble_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=BLEThread.ble_adv_data,
                                                               own_addr_type=2, ble_adv_int_min=32,
                                                                   ble_adv_int_max=160)
            time.sleep(5)
            self.power_save()
            logger().info("\n....Remote device starts Scanning....\n")
            self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=BLEThread.ble_public_address)
            time.sleep(20)
            logger().info("....Stopping BLE Scan....")
            self.ble_client.interfaces.bluetooth.stop_scanning()
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert len(found_devices) > 0, "No devices found"
            logger().info("\n Scanned devices: {}\n".format(found_devices))
            logger().info(f"....Fetching Data from BTMon Logs....")
            records = self.fetch_data_from_btmon_logs(self.bt_mon_log_file_name)
            resolved_addresses = set()
            for record in records:
                if BLEThread.ble_adv_data in record:
                    assert record[2] == 'Random', "....The Resolved address isn't Random...."
                    assert record[4] == 'Resolvable', "....The address type isn't Resolvable...."
                    resolved_addresses.add(record[3])
            logger().info(f"The Resolved addresses with advertising data {BLEThread.ble_adv_data} are {resolved_addresses}")
            assert BLEThread.ble_public_address not in resolved_addresses, "\n\n....ADDRESS ISN'T RESOLVED....\n\n"
            self.ble_dut.interfaces.wifi.ble_stop_advertising()

    # Testcase 478666: Verify advertising start/stop using public/random addresses and UNDIR_CONN adv_type
    def testcase_478666(self):
        records = self.advertise_dut_using_address(BLEThread.ble_public_address, "Public", 0, ["UNDIR_CONN", 128])
        found_desired_record = self.validate_address(records, BLEThread.ble_public_address, "Public")
        assert found_desired_record[
                   1] == "Connectable undirected - ADV_IND (0x00)", f"Advertisement type doesn't match for : {BLEThread.ble_public_address}"
        self.ble_client.interfaces.bluetooth.close()
        logger().info(f"Setting BLE address to random LE address: {BLEThread.ble_private_address}...")
        self.ble_dut.interfaces.wifi.set_ble_address(ble_address=BLEThread.ble_private_address)
        records = self.advertise_dut_using_address(BLEThread.ble_private_address, "Random", 1, ["UNDIR_CONN", 128])
        time.sleep(5)
        found_desired_record = self.validate_address(records, BLEThread.ble_private_address, "Random")
        assert found_desired_record[
                   1] == "Connectable undirected - ADV_IND (0x00)", f"Advertisement type doesn't match for : {BLEThread.ble_private_address}"

    # Testcase 478666: Verify advertising start/stop using public/random addresses and UNDIR_CONN adv_type
    def testcase_478667(self):
        records = self.advertise_dut_using_address(BLEThread.ble_public_address, "Public", 0, ["UNDIR_SCAN", 130])
        found_desired_record = self.validate_address(records, BLEThread.ble_public_address, "Public")
        assert found_desired_record[
                   1] == "Scannable undirected - ADV_SCAN_IND (0x02)", f"Advertisement type doesn't match for : {BLEThread.ble_public_address}"
        self.ble_client.interfaces.bluetooth.close()
        logger().info(f"Setting BLE address to random LE address: {BLEThread.ble_private_address}...")
        self.ble_dut.interfaces.wifi.set_ble_address(ble_address=BLEThread.ble_private_address)
        records = self.advertise_dut_using_address(BLEThread.ble_private_address, "Random", 1, ["UNDIR_SCAN", 130])
        time.sleep(5)
        found_desired_record = self.validate_address(records, BLEThread.ble_private_address, "Random")
        assert found_desired_record[
                   1] == "Scannable undirected - ADV_SCAN_IND (0x02)", f"Advertisement type doesn't match for : {BLEThread.ble_private_address}"

    # Method to enable power save
    def power_save(self):
        logger().info("Enabling Power Save...")
        enable_wifi_ps = self.ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, '..failed to enable WiFi Power Save..'
        enable_bt_ps = self.ble_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, '..failed to enable BT Power save..'

    # Method to start advertising and validate the address from btmon logs
    def advertise_dut_using_address(self, ble_address, address_type, own_addr_type, ble_adv_type):
        with BleLogs(
                start_collecting_logs=True,
                bt_log_path=self.bt_mon_log_file_name
        ) as bt_logs:
            logger().info(
                f"Starting BLE Advertisement with {address_type} LE address: {ble_address} and adv_type {ble_adv_type[0]}...")
            self.ble_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=BLEThread.ble_adv_data,
                                                               own_addr_type=own_addr_type,
                                                               ble_adv_type=ble_adv_type[1])
            if self.power_save_enable:
                self.power_save_enable = False
                self.power_save()
            logger().info("Scanning for BLE devices...")
            self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_address)
            time.sleep(5)
            self.ble_client.interfaces.bluetooth.stop_scanning()
            logger().info("Stopping BLE Advertisement...")
            self.ble_dut.interfaces.wifi.ble_stop_advertising()
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert len(found_devices) > 0, "No devices found"
            logger().info("Found devices: {}".format(found_devices))
        return self.fetch_data_from_btmon_logs(bt_mon_log_file_name=self.bt_mon_log_file_name)

    # Method to fetch data from btmon logs
    def fetch_data_from_btmon_logs(self, bt_mon_log_file_name):
        with open(bt_mon_log_file_name, "r") as bt_mon_log_file:
            records = set()
            log_content = bt_mon_log_file.read()
            pattern = r'> HCI Event: LE Meta Event \(0x\w+\) plen \d+\s+#\d+ \[hci\d\] \d+:\d+:\d+\.\d+\n' \
                      r'      LE Advertising Report \(0x0\d\)\n' \
                      r'        Num reports: (\d+)\n' \
                      r'        Event type: ((?:\w+\s\w+?){1,2} - (?:\w+?) \(0x0\d\))\n' \
                      r'        Address type: (\w+) \(0x0\d\)\n' \
                      r'        Address: ([0-9A-Za-z:]+) \((OUI [0-9A-Fa-f-]+|Non-Resolvable|Resolvable)\)\n' \
                      r'        Data length: (\d+)\n' \
                      r'        Flags: 0x0\d+\n' \
                      r'          LE General Discoverable Mode\n' \
                      r'          BR/EDR Not Supported\n' \
                      r'        Name \(complete\): (\w+)\n' \
                      r'        RSSI: (-\d+ dBm) \(0x[0-9a-fA-F]+\)'
            matches = re.findall(pattern, log_content)
            for match in matches:
                records.add(match)
            logger().info(f"\n....................\n{records}\n....................\n")
            return records

    def validate_address(self, records, ble_address, address_type):
        found_desired_record = ()
        for record in records:
            if ble_address in record:
                found_desired_record = record
                break
        assert len(found_desired_record) > 0, f"Record not found for {ble_address}"
        assert found_desired_record[2] == address_type, f"Address type is not {address_type} for {ble_address}"
        return found_desired_record


# BIT Configuration for the test cases
pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                              Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                               Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_verify_advertising_start_stop_using_public_random_addresses_c652922(ble_dut, ble_client,
                                                                                     sl_collections):
    """
        Test Case 485433: Verify advertising start/stop using public/random addresses

        This test case verifies the BLE advertising functionality with both public and random addresses.
        It creates a BLEThread instance and starts it. The BLEThread instance is responsible for starting
        the BLE, setting the BLE address to public, starting advertising, validating the address, setting
        the BLE address to random, starting advertising again, and validating the address.

        Parameters:
        ble_dut: The BLE device under test.
        ble_client: The BLE client device used for testing.
        sl_collections: The test collections.

        Raises:
        Exception: If there is an error during the test execution.
    """
    bt_mon_log_file_name = (
        f"reports/test_ble_sdk_verify_advertising_start_stop_using_public_random_addresses"
        f"c485433_{int(time.time())}.log")
    testcase_id = 485433
    try:
        ble_thread = BLEThread(ble_dut=ble_dut, ble_client=ble_client, testcase_id=testcase_id, power_save_enable=True, bt_mon_log_file_name=bt_mon_log_file_name)
        ble_thread.start()
        ble_thread.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_verify_adv_types_resolvable_private_address_diff_adv_intervals_c652923(ble_dut, ble_client,
                                                                                        sl_collections):
    """
        Test Case 485438: Verify advertisement types with resolvable private address and different advertisement intervals

        This test case verifies the BLE advertising functionality with resolvable private address and different
        advertisement intervals. It creates a BLEThread instance and starts it. The BLEThread instance is responsible
        for starting the BLE, setting the BLE address to a resolvable private address, starting advertising with
        different intervals, and validating the address.

        Parameters:
        ble_dut: The BLE device under test.
        ble_client: The BLE client device used for testing.
        sl_collections: The test collections.

        Raises:
        Exception: If there is an error during the test execution.
        """
    bt_mon_log_file_name = f"reports" \
                           f"/test_ble_sdk_verify_adv_types_resolvable_private_address_diff_adv_intervals_c485438{int(time.time())}.log"
    testcase_id = 485438
    try:
        ble_thread = BLEThread(ble_dut=ble_dut, ble_client=ble_client, testcase_id=testcase_id,
                                power_save_enable=True, bt_mon_log_file_name=bt_mon_log_file_name)
        ble_thread.start()
        ble_thread.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_verify_address_resolution_enable_disable_c652924(ble_dut, ble_client, sl_collections):
    """
    Test Case 485439: Verify address resolution enable/disable functionality

    This test case verifies the BLE address resolution enable/disable functionality. It creates a BLEThread instance
    and starts it. The BLEThread instance is responsible for adding the device to the BLE resolve list, enabling
    address resolution, starting BLE advertising, starting BLE scanning on the client, validating the resolved addresses,
    and disabling address resolution.

    Parameters:
    ble_dut: The BLE device under test.
    ble_client: The BLE client device used for testing.
    sl_collections: The test collections.

    Raises:
    Exception: If there is an error during the test execution.
    """
    testcase_id = 485439
    bt_mon_log_file_name = (
        f"reports/test_ble_sdk_verify_address_resolution_enable_disable"
        f"c485439_{int(time.time())}.log")
    try:
        ble_thread = BLEThread(ble_dut=ble_dut, ble_client=ble_client, testcase_id=testcase_id, power_save_enable=True, bt_mon_log_file_name=bt_mon_log_file_name)
        ble_thread.start()
        ble_thread.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)



@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_verify_advertising_start_stop_using_public_random_addresses_with_UNDIR_CONN_c652925(ble_dut,
                                                                                                     ble_client,
                                                                                                     sl_collections):
    """
        Test Case 478666: Verify advertising start/stop using public/random addresses with UNDIR_CONN

        This test case verifies the BLE advertising functionality with both public and random addresses using UNDIR_CONN.
        It creates a BLEThread instance and starts it. The BLEThread instance is responsible for starting
        the BLE, setting the BLE address to public, starting advertising with UNDIR_CONN, validating the address, setting
        the BLE address to random, starting advertising again with UNDIR_CONN, and validating the address.

        Parameters:
        ble_dut: The BLE device under test.
        ble_client: The BLE client device used for testing.
        sl_collections: The test collections.

        Raises:
        Exception: If there is an error during the test execution.
    """
    bt_mon_log_file_name = (
        f"reports/test_ble_sdk_verify_advertising_start_stop_using_public_random_addresses_with_UNDIR_CONN"
        f"c478666_{int(time.time())}.log")
    testcase_id = 478666
    try:
        ble_thread = BLEThread(ble_dut=ble_dut, ble_client=ble_client, testcase_id=testcase_id, power_save_enable=True, bt_mon_log_file_name=bt_mon_log_file_name)
        ble_thread.start()
        ble_thread.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_verify_advertising_start_stop_using_public_random_addresses_with_UNDIR_SCAN_c652926(ble_dut,
                                                                                                     ble_client,
                                                                                                     sl_collections):
    """
        Test Case 478667: Verify advertising start/stop using public/random addresses with UNDIR_SCAN

        This test case verifies the BLE advertising functionality with both public and random addresses using UNDIR_SCAN.
        It creates a BLEThread instance and starts it. The BLEThread instance is responsible for starting
        the BLE, setting the BLE address to public, starting advertising with UNDIR_SCAN, validating the address, setting
        the BLE address to random, starting advertising again with UNDIR_SCAN, and validating the address.

        Parameters:
        ble_dut: The BLE device under test.
        ble_client: The BLE client device used for testing.
        sl_collections: The test collections.

        Raises:
        Exception: If there is an error during the test execution.
    """
    bt_mon_log_file_name = (
        f"reports/test_ble_sdk_verify_advertising_start_stop_using_public_random_addresses_with_UNDIR_SCAN"
        f"c478667_{int(time.time())}.log")

    testcase_id = 478667
    try:
        ble_thread = BLEThread(ble_dut=ble_dut, ble_client=ble_client, testcase_id=testcase_id, power_save_enable=True, bt_mon_log_file_name=bt_mon_log_file_name)
        ble_thread.start()
        ble_thread.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_verify_address_resolution_enable_c652927(ble_dut, ble_client, sl_collections):
    """
        Test Case 477084: Verify address resolution enable functionality

        This test case verifies the BLE address resolution enable functionality. It creates a BLEThread instance
        and starts it. The BLEThread instance is responsible for adding the device to the BLE resolve list, enabling
        address resolution, starting BLE advertising, starting BLE scanning on the client, validating the resolved addresses.

        Parameters:
        ble_dut: The BLE device under test.
        ble_client: The BLE client device used for testing.
        sl_collections: The test collections.

        Raises:
        Exception: If there is an error during the test execution.
    """
    testcase_id = 477084
    bt_mon_log_file_name = (
        f"reports/test_ble_sdk_verify_address_resolution_enable_c477084"
        f"{int(time.time())}.log")
    try:
        ble_thread = BLEThread(ble_dut=ble_dut, ble_client=ble_client, testcase_id=testcase_id, power_save_enable=True, bt_mon_log_file_name=bt_mon_log_file_name)
        ble_thread.start()
        ble_thread.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)
