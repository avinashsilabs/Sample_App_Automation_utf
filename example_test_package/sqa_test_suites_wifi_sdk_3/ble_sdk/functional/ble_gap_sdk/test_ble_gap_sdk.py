import re
import pytest
import time
import datetime
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap,\
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap,\
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utf_config import UtfConfig
from utf.utils.time_measurer import TimeMeasurer

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capability enables
        4. Opens Bt socket and connects to the remote client.
        5. Verifies ping after the connection.

    Author: Vishakha
"""

'''=================== Ble-gap IO test cases ===================== '''

def get_ble_client_addr(ble_client):
    ble_client_addr = None
    logger().info(f"fetching BLE client Address: '{ble_client.name}' ")
    rc, stdout, stderr = ble_client.interfaces.bluetooth.shell.execute(f"hcitool dev")
    if rc == 0:
        pattern = r'([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})[\s]'
        ble_client_addr = re.search(pattern, stdout.decode()).group(0).strip()
    else:
        logger().error(f"Unable to fetch ble_client_address:\n{stderr}")
    assert ble_client_addr, "Unable to fetch ble_client_address"
    return ble_client_addr

def check_for_devices_in_scanned_results(ble_interface, bt_dut_address, adv_data):
    """ This function is used to check for devices in scan results """
    sw = Stopwatch()
    previously_found_devices = {}
    while sw.elapsed_sec < 30:
        found_devices = ble_interface.get_devices()
        if previously_found_devices != found_devices:
            logger().info(f"BLE scan results :{found_devices}")
            previously_found_devices = found_devices
        if (
                bt_dut_address in found_devices
                and found_devices[bt_dut_address] == adv_data
        ):
            return True
    return False

class connectasmaster:
    def __init__(self, ble_dut, ble_client, sl_collections, ble_dut_address=None, ble_capability=None, set_smp=0):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.sl_collections = sl_collections
        self.ble_capability = ble_capability
        self.set_smp = set_smp

    def ble_connect(self):
        logger().info("Initialising BLE")
        if self.ble_capability is None:
            logger().info("default capability.....")
            self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_start()
        else:
            logger().info("selected capability.....")
            self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_start(capability=self.ble_capability, set_smp=self.set_smp)
        assert self.ble_dut_address, "failed to initiate ble in dut"

        logger().info(f"Initiating connection.......")
        self.sl_collections.ble_connection(wifi_dut=self.ble_dut,
                                           ble_client=self.ble_client,
                                           ble_dut_address=self.ble_dut_address,
                                           mode="master")
        time.sleep(20)
        logger().info(f"\n\n ***** Successfully connected with Remote *****\n\n")
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"state_int==============>>,  {state_int}")

    def power_save(self):
        self.ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

    def ble_disconnect(self, disconnect_from="remote"):
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)


pytestmark=[
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS |
                            Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC |
                            Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID |
                            Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                            Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE |
                            Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
                                       # Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                               Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
       },
    )
]



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_displayonly_C19851(ble_dut, ble_client, sl_collections):
    """
    Test "display only" IO capability in Slave mode as SMP responder
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("Start smp scan from the remote device")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "failed to initiate ble in remote device"

        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        logger().info("Check the dut is listed...")
        ble_client.interfaces.bluetooth.get_devices()

        logger().info("Connect to the dut with mac address..")
        connect_time = datetime.datetime.now()
        ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
        logger().info(f"connect_time:  {connect_time}")
        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        logger().info("Connection successfully stable for 60sec")
        ble_dut.interfaces.bluetooth.ble_advertising = False

        logger().info("Checking connection status of BLE")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        logger().info(f"state_int==============>>,  {state_int}")
        if (state_int > 0):
            logger().info("Disconnecting the bt host....")
            disconnect_time = datetime.datetime.now()
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
            logger().info(f"disconnect_time  {disconnect_time}")
            assert "unable to disconnect since the connection never existed"
            logger().info(f"connection existed for {disconnect_time - connect_time}")
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_display_yesno_C19852(ble_dut, ble_client, sl_collections):
    """
    Test "Display Yes No" capability in Slave mode as SMP responder
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=1, set_smp=1)
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("Start smp scan from the remote device")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "failed to initiate ble in remote device"

        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        logger().info("Check the dut is listed...")
        ble_client.interfaces.bluetooth.get_devices()

        logger().info("Connect to the dut with mac address..")
        connect_time = datetime.datetime.now()
        ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
        logger().info(f"connect_time:  {connect_time}")

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        logger().info("Connection successfully stable for 60sec")
        ble_dut.interfaces.bluetooth.ble_advertising = False

        logger().info("Checking connection status of BLE")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        logger().info(f"state_int==============>>,  {state_int}")
        if (state_int > 0):
            logger().info("Disconnecting the bt host....")
            disconnect_time = datetime.datetime.now()
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
            logger().info(f"disconnect_time  {disconnect_time}")
            assert "unable to disconnect since the connection never existed"
            logger().info(f"connection existed for {disconnect_time - connect_time}")
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_keyboard_only_C19853(ble_dut, ble_client, sl_collections):
    """
    Test "Keyboard only" IO capability in Slave mode as SMP responder
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=2, set_smp=1)
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("Start smp scan from the remote device")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "failed to initiate ble in remote device"

        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        logger().info("Check the dut is listed...")
        ble_client.interfaces.bluetooth.get_devices()

        logger().info("Connect to the dut with mac address..")
        connect_time = datetime.datetime.now()
        ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
        logger().info(f"connect_time:  {connect_time}")

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        logger().info("Connection successfully stable for 60sec")
        ble_dut.interfaces.bluetooth.ble_advertising = False

        logger().info("Checking connection status of BLE")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        logger().info(f"state_int==============>>,  {state_int}")
        if (state_int > 0):
            logger().info("Disconnecting the bt host....")
            disconnect_time = datetime.datetime.now()
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
            logger().info(f"disconnect_time  {disconnect_time}")
            assert "unable to disconnect since the connection never existed"
            logger().info(f"connection existed for {disconnect_time - connect_time}")
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_No_input_output_C19854(ble_dut, ble_client, sl_collections):
    """
    Test "No input no output" IO capability in Slave mode as SMP responder
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=3, set_smp=1)
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("Start smp scan from the remote device")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "failed to initiate ble in remote device"

        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        logger().info("Check the dut is listed...")
        ble_client.interfaces.bluetooth.get_devices()

        logger().info("Connect to the dut with mac address..")
        connect_time = datetime.datetime.now()
        ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
        logger().info(f"connect_time:  {connect_time}")

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        logger().info("Connection successfully stable for 60sec")
        ble_dut.interfaces.bluetooth.ble_advertising = False

        logger().info("Checking connection status of BLE")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        logger().info(f"state_int==============>>,  {state_int}")
        if (state_int > 0):
            logger().info("Disconnecting the bt host....")
            disconnect_time = datetime.datetime.now()
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
            logger().info(f"disconnect_time  {disconnect_time}")
            assert "unable to disconnect since the connection never existed"
            logger().info(f"connection existed for {disconnect_time - connect_time}")
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)



'''======================= Ble-gap IO test cases dut as initiator ====================='''



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_displayonly_C19855(ble_dut, ble_client, sl_collections):
    """
    Test "display only" IO capability in Master mode as SMP initiator
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("start ble connection......")
        ble_obj = connectasmaster(ble_dut, ble_client, sl_collections, ble_capability=0, set_smp=1)
        ble_dut_address = ble_obj.ble_connect()
        logger().info(f"BLE DUT address: {ble_dut_address} ......")

        logger().info("enabling the power save modes ")
        ble_obj.power_save()
        logger().info(f"Sucessfully Enabled Powersave")
        time.sleep(60)

        logger().info(f"Initiating BLE disconnection from DUT")
        ble_obj.ble_disconnect()
        logger().info(f"Sucessfully BLE disconncted")

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_display_yesno_C19856(ble_dut, ble_client, sl_collections):
    """
    Test "Display Yes/No" IO capability in Master mode as SMP initiator
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("start ble connection......")
        ble_obj = connectasmaster(ble_dut, ble_client, sl_collections, ble_capability=1, set_smp=1)
        ble_dut_address = ble_obj.ble_connect()
        logger().info(f"BLE DUT address: {ble_dut_address} ......")

        logger().info("enabling the power save modes ")
        ble_obj.power_save()
        logger().info(f"Sucessfully Enabled Powersave")
        time.sleep(60)

        logger().info(f"Initiating BLE disconnection from DUT")
        ble_obj.ble_disconnect()
        logger().info(f"Sucessfully BLE disconncted")

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_keyboard_only_C19857(ble_dut, ble_client, sl_collections):
    """
    Test "Keyboard only" IO capability in Master mode as SMP initiator
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("start ble connection......")
        ble_obj = connectasmaster(ble_dut, ble_client, sl_collections, ble_capability=2, set_smp=1)
        ble_dut_address = ble_obj.ble_connect()
        logger().info(f"BLE DUT address: {ble_dut_address} ......")

        logger().info("enabling the power save modes ")
        ble_obj.power_save()
        logger().info(f"Sucessfully Enabled Powersave")
        time.sleep(60)

        logger().info(f"Initiating BLE disconnection from DUT")
        ble_obj.ble_disconnect()
        logger().info(f"Sucessfully BLE disconncted")

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_io_cap_no_input_output_C19858(ble_dut, ble_client, sl_collections):
    """
    Test "No input no output" IO capability in Master mode as SMP initiator
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("start ble connection......")
        ble_obj = connectasmaster(ble_dut, ble_client, sl_collections, ble_capability=3, set_smp=1)
        ble_dut_address = ble_obj.ble_connect()
        logger().info(f"BLE DUT address: {ble_dut_address} ......")

        logger().info("enabling the power save modes ")
        ble_obj.power_save()
        logger().info(f"Sucessfully Enabled Powersave")
        time.sleep(60)

        logger().info(f"Initiating BLE disconnection from DUT")
        ble_obj.ble_disconnect()
        logger().info(f"Sucessfully BLE disconncted")

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)



"""============================ Ble-gap dut scan for adv types ============================================="""


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_directed_connectable_adv_C19802(ble_dut, ble_client, bt_logs, sl_collections):
    """
    Verify BLE Directed connectable advertisement
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    :param bt_logs: BT logs
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_directed_connectable_adv_C19802.logs_{int(time.time())}"):
            logger().info("Initializing BLE")
            ble_dut_address = ble_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, "Unable to fetch bluetooth address from DUT"
            logger().info(f"bt_dut_address : {ble_dut_address}")
            logger().info("Initiating scan from remote BLE device")

            ble_client.interfaces.bluetooth.hci_tool_manager.start_lescan()
            ble_client_address = get_ble_client_addr(ble_client)
            logger().info(f"BLE_CLIENT_ADDR : {ble_client_address}")

            logger().info("Advertising the DUT in Connectable directed ADV mode")
            ble_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=129, ble_dir_addr=ble_client_address,
                                                          ble_advertising_data="SI917")
            device_found = check_for_devices_in_scanned_results(ble_interface=ble_client.interfaces.bluetooth,
                                                                bt_dut_address=ble_dut_address,
                                                                adv_data=ble_dut.interfaces.wifi.ble_advertising_data)
            logger().info("Enabling Wlan and BLE power save ")
            if power_save:
                ble_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                             psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info(
                f"Getting Remote BLE characteristics by passing address {ble_dut.interfaces.wifi.ble_address} from BTmon logs")
            bt_logs.device_characteristics(ble_dut.interfaces.wifi.ble_address)
            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")
            assert "Connectable directed - ADV_DIRECT_IND (0x01)" in bt_logs.device_adv_type, "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            ble_client.interfaces.bluetooth.close()
            time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_connectable_undirected_adv_C19805(ble_dut, ble_client, sl_collections):
    """
    Verify BLE Scan the Connectable Undirected advertising devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info("start ble client...")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0xA0 0x00 "  # Advertising_Interval_Min
                           "0xA0 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert ble_client_address, "failed to initiate ble in remote device"
        logger().info(f"ble client addr..{ble_client_address}")
        time.sleep(5)
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                    psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        scan_status = False
        if (ble_client_address in str(scan_result)) and ("report_type:0" in str(scan_result)):
            logger().info("Advertisement type found in adv report is : report_type:0")
            scan_status = True
        assert scan_status, "no bt device found with adv type 0x00"

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


'''Device advertising within 1.3sec, so unable to capture while scanning. Need to recheck this testcase.'''
@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC |
                        Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                        Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_connectable_directed_adv_C19806(ble_dut, ble_client, sl_collections):
    """
    Verify ble scan with directed Connectable advertising devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "unable to fetch bd address"
        logger().info("start ble client...")
        logger().info(f"ble_dut_address {ble_dut_address}")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        time.sleep(1)
        assert ble_client_address, "failed to initiate ble in remote device"
        logger().info(f"ble client add..{ble_client_address}")
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()

        mac_list = ble_dut_address.split(":")
        mac_list.reverse()
        mac_list = ["0x" + s for s in mac_list]
        peer_address = " ".join(mac_list)
        logger().info(f"peer_address: {peer_address}")

        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0xA0 0x00 "
                           "0xA0 0x00 "
                           "0x01 "
                           "0x00 "
                           "0x00 "
                           f"{peer_address} "
                           "0x07 "
                           "0x00"
        )
        assert ble_client_address, "failed to initiate ble in remote device"

        logger().info(f"ble client add..{ble_client_address}")
        logger().info(f"remote address:*********{peer_address}*******")
        time.sleep(5)

        logger().info("Start scanning....")
        result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        logger().info(f" scan result '{result}")

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        scan_results = result.splitlines()
        logger().info(f"scan_results: **********{scan_results}**********")
        scan_status = False
        for line in scan_results:
            line = str(line)
            logger().info("checking for remote device Advertisement type and BD address")
            if "rsi_ble_simple_central_on_adv_report_event" in line:
                logger().info(f"**************Advertise report :{line}**********")
                if (ble_client_address in line) and ("report_type:1" in line):
                    logger().info("Advertisement type found 0x01 in adv report")
                    scan_status = True
                    break
        assert scan_status, "no bt device found with adv type 0x01"

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_non_connectable_undirected_adv_C19807(ble_dut, ble_client, sl_collections):
    """
    Verify ble scan with Undirected Non-Connectable advertising devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to start ble in dut"
        logger().info("start ble client...")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0xA0 0x00 "
                           "0xA0 0x00 "
                           "0x03 "
                           "0x00 "
                           "0x00 "
                           "0x00 0x00 0x00 0x00 0x00 0x00 "
                           "0x07 "
                           "0x00"
        )
        assert ble_client_address, "failed to initiate ble in remote device"
        logger().info(f"ble client add..{ble_client_address}")
        time.sleep(5)
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        scan_status = False
        if (ble_client_address in str(scan_result)) and ("report_type:3" in str(scan_result)):
            logger().info("Advertisement type found in adv report is : report_type:3")
            scan_status = True
        assert scan_status, "no bt device found with adv type 0x03"

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scannable_undirected_adv_C19808(ble_dut, ble_client, sl_collections):
    """
    Verify ble scan the Undirected scannable advertising devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to start ble in dut"
        logger().info("start ble client...")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0xA0 0x00 "
                           "0xA0 0x00 "
                           "0x02 "
                           "0x00 "
                           "0x00 "
                           "0x00 0x00 0x00 0x00 0x00 0x00 "
                           "0x07 "
                           "0x00"
        )
        assert ble_client_address, "failed to initiate ble in remote device"
        logger().info(f"ble client add..{ble_client_address}")
        time.sleep(5)
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        scan_status = False
        if (ble_client_address in str(scan_result)) and ("report_type:2" in str(scan_result)):
            logger().info("Advertisement type found in adv report is : report_type:2")
            scan_status = True
        assert scan_status, "no bt device found with adv type 0x02"

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dut_slave_connect_C19832(ble_dut, ble_client, sl_collections):
    """
    Configure DUT in Salve mode and verify connectivity
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info(" ======= set local name")
        set_local_name = "DUT_SLAVE_CON"
        logger().info(f" ======= Setting BLE local name : {set_local_name}")
        time.sleep(5)
        ble_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = ble_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f" ======= Getting the local name : {status}")
        assert set_local_name == status, "Set local name and get local name not matched "

        logger().info("Start Ble...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info("set dut in adv mode...")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        logger().info("start ble scan from remote le device...")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()

        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices
        assert (
                found_devices[ble_dut.interfaces.wifi.ble_address]
                == ble_dut.interfaces.bluetooth.ble_advertising_data
        )
        logger().info("connect to dut from remote le device....")
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        assert ble_dut_address, "unable to connect to the given address"
        time.sleep(30)

        ble_dut.interfaces.bluetooth.ble_advertising = False

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"state_int==============>>,  {state_int}")
        if (state_int > 0):
            logger().info("disconnecting the dut..")
            ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
            assert "unable to disconnect since the connection never existed"
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable", "ble_disconnect"])
def test_ble_sdk_adv_state_in_scan_C19840(ble_dut, ble_clients, sl_collections):
    """
    Verify BLE advertise in scanning state using 2 RASPI
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_adv_state_in_scan_C19840.logs_{int(time.time())}"):
            scan_result = ""
            assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            logger().info("INITIATING BLE SERVICE IN DUT")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "FAILED TO INITIATE BLE IN DUT"

            logger().info(" **** START ADVERTISING FROM DUT **** ")
            ble_dut.interfaces.bluetooth.ble_start_advertising(ble_dir_addr = ble_dut_address)

            logger().info(" **** START SCANNING DUT FROM REMOTE DEVICE 1 **** ")
            ble_client_address1 = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address1, "FAILED TO INITIATE BLE IN REMOTE DEVICE 1"
            logger().info(f" **** ble_client_address1: {ble_client_address1} **** ")
            time.sleep(15)
            found_devices_list = ble_client1.interfaces.bluetooth.get_devices()
            logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 1:*********{found_devices_list}*****************")
            assert ble_dut.interfaces.bluetooth.ble_address in found_devices_list, "DUT ISN'T LISTED IN SCAN RESULTS"
            logger().info("FOUND DUT BD ADDRESS IN SCAN RESULTS")

            logger().info(" **** START ADVERTISING FROM REMOTE DEVICE 2 **** ")
            ble_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address2, "UNABLE TO GET BLE CLIENT ADDRESS"
            logger().info(f"ble_client_address2: {ble_client_address2}")

            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address2, timeout=120)
            time.sleep(15)
            events = ble_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                    if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                        logger().info(f" event data : {event.event_data}")
                        scan_result = event.event_data

            logger().info(f"SCAN RESULT IS: '{scan_result}")
            assert str(ble_client_address2) in str(scan_result), "REMOTE DEVICE 2 ADDRESS ISN'T PRESENT IN DUT SCAN RESULTS"
            logger().info("SUCCESSFULLY FOUND REMOTE DEVICE 2 IN DUT SCAN RESULTS")

            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info("DISABLING ADVERTISEMENT AND SCANNING FROM RASPI AND DUT")
            ble_dut.interfaces.wifi.ble_stop_scanning()
            ble_client2.interfaces.bluetooth.stop_advertising()
            ble_client1.interfaces.bluetooth.stop_scanning()
            ble_dut.interfaces.wifi.ble_stop_advertising()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


# " ============ ble-gap pdu length test cases ====================== "

'''Dependent JIRA SI91X-13954'''
@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC |
                        Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                        Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_continuous_scan_C19819(ble_dut, ble_client, sl_collections):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval same value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_scan_window = 32  # 0x20 in hexadecimal
            ble_scan_interval = 32  # 0x20 in hexadecimal
            logger().info("start ble in dut")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "ble initialization failed in dut"
            t_end = time.time() + 60 * 3
            while time.time() < t_end:
                ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
                assert ble_client_address, f"ble initialization failed in remote device"

                time.sleep(5)
                ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address,
                                                                ble_scan_interval=int(ble_scan_interval / 0.625),
                                                                ble_scan_window=int(ble_scan_window / 0.625), timeout=120)
                time.sleep(2)

                logger().info("enabling the power save modes ")
                ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                             psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

                logger().info("stop scanning")
                ble_dut.interfaces.bluetooth.ble_stop_scanning()
                logger().info("stop advertising")
                ble_client.interfaces.bluetooth.stop_advertising()
                time.sleep(5)
                ble_client.interfaces.bluetooth.close()
                time.sleep(5)
        logger().info(f"time taken for test {t.duration}")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable", "ble_disconnect"])
def test_ble_sdk_continuous_scan_C19820(ble_dut, ble_client, sl_collections, ble_sniffer, wifi_sniffer):
    """
    Verify BLE Continuous Scanning by configuring scan window less than scan interval
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            scan_result = ""
            ble_scan_window = 32  # 0x0020 in hexadecimal
            ble_scan_interval = 160  # 0x00A0 in hexadecimal
            logger().info("start ble in dut")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "ble initialization failed in dut"
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"ble initialization failed in remote device"
            time.sleep(5)
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address,
                                                            ble_scan_interval=int(ble_scan_interval / 0.625),
                                                            ble_scan_window=int(ble_scan_window / 0.625), timeout=60)
            scan_duration_in_min = 3
            time.sleep(60 * scan_duration_in_min)
            events = ble_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                    if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                        logger().info(f" event data : {event.event_data}")
                        scan_result = event.event_data
            logger().info(f"SCAN RESULT IS: '{scan_result}")

            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            logger().info("stop advertising")
            ble_client.interfaces.bluetooth.stop_advertising()
            time.sleep(5)
            ble_client.interfaces.bluetooth.close()
            time.sleep(5)
        logger().info(f"time taken for test {t.duration}")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_resp_8_bytes_C19821(ble_dut, ble_client, sl_collections):
    """
    Verify ble scan and read the advertising PDU length(8 bytes) of remote device
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble dut....")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("start ble client with pdu length 8 bytes....")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                           "0x40 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
            , scan_resp_name_params="0x00 0x09 0x09 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                    "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                    "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
        )
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(1)
        logger().info("Start ble scanning...")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        logger().info("verifying client addr, is available in scan list...")
        assert str(ble_client_address) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {ble_client_address}")

        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_resp_20_bytes_C19822(ble_dut, ble_client, sl_collections):
    """
    Verify ble scan and read the advertising PDU length(20 bytes) of remote device
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble dut....")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("start ble client with pdu length 8 bytes....")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                           "0x40 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
            , scan_resp_name_params="0x0c 0x0b 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 0x65 0x61 "
                                    "0x61 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                    "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
        )
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(1)
        logger().info("Start ble scanning...")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        logger().info("verifying client addr, is available in scan list...")
        assert str(ble_client_address) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info("found BT client address :{ble_client_address}")

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_resp_30_bytes_C19823(ble_dut, ble_client, sl_collections):
    """
    Verify ble scan and read the advertising PDU length(30 byte)
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble dut....")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("start ble client with pdu length 30 bytes....")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                           "0x40 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
            , scan_resp_name_params="0x16 0x15 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 "
                                    "0x65 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 "
                                    "0x61 0x61 0x61 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
        )
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(1)
        logger().info("Start ble scanning...")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        logger().info("verifying client addr, is available in scan list...")
        assert str(ble_client_address) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {ble_client_address}")

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_resp_39_bytes_C19824(ble_dut, ble_client, sl_collections):
    """
    Verify ble scan and read the advertising PDU length(39byte)
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble dut....")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("start ble client with pdu length 30 bytes....")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=ble_dut_address,
            hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                           "0x40 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
            , scan_resp_name_params="0x1F 0x1E 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 0x65 0x61 "
                                    "0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 "
                                    "0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x00 0x00 "
        )
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(1)
        logger().info("Start ble scanning...")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        logger().info("verifying client addr, is available in scan list...")
        assert str(ble_client_address) in str(scan_result), "failed to find client bt address in scan list...."
        logger().info(f"found BT client address : {ble_client_address}")

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dut_master_undirected_connectable_c19833(ble_dut, ble_client, sl_collections):
    """
    Configure DUT in Master and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_dut_master_undirected_connectable_c19833.logs_{int(time.time())}"):
            logger().info("start ble...")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "unable to fetch bd address"
            logger().info(f"Configuring Remote LE device in Undirected connectable advertising mode")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address,
                hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                               "0x40 0x00 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x00 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00"  # Advertising_Filter_Policy
                , scan_resp_name_params="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                        "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                        "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                        "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
            )
            assert ble_client_address, "failed to initiate ble in remote device"
            logger().info("Start scanning....")
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)
            logger().info(f"DUT initiating BLE connection with ble_client device")
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address)

            logger().info("Check connection status of BLE")
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
            logger().info("DUT is not disconnected from BLE")
            ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dut_master_directed_connectable_c19834(ble_dut, ble_client, sl_collections):
    """
    Configure DUT in Master mode and verify connectivity with Directed connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_dut_master_directed_connectable_c19834.logs_{int(time.time())}"):
            logger().info("start ble...")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "unable to fetch bd address"
            logger().info(f"Configuring Remote LE device in Undirected connectable advertising mode")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address,
                hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                               "0x40 0x00 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x01 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00 "  # Advertising_Filter_Policy
                , scan_resp_name_params="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                        "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                        "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                        "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
            )
            time.sleep(1)
            assert ble_client_address, "failed to initiate ble in remote device"
            logger().info(f"ble client add..{ble_client_address}")
            ble_client.interfaces.bluetooth.stop_advertising()
            time.sleep(5)
            ble_client.interfaces.bluetooth.close()

            mac_list = ble_dut_address.split(":")
            mac_list.reverse()
            mac_list = ["0x" + s for s in mac_list]
            peer_address = " ".join(mac_list)
            logger().info(f"peer_address {peer_address}")
            time.sleep(5)

            hci_adv_params = f"0x20 0x00 0x20 0x00 0x01 0x00 0x00 {peer_address} 0x07 0x00"
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address, hci_adv_params=hci_adv_params)
            assert ble_client_address, "failed to initiate ble in remote device"

            logger().info("Start scanning....")
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)

            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()

            logger().info(f"DUT initiating BLE connection with ble_client device")
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address)

            logger().info("Check connection status of BLE")
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
            logger().info("DUT is not disconnected from BLE")
            ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_undirected_conn_verification_c19835(ble_dut, ble_client, sl_collections):
    """
    Verify BLE connect disconnect functionality
    :param ble_dut:  Fixture parameter to issue command in DUT
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_undirected_conn_verification_c19835.logs_{int(time.time())}"):
            logger().info(f"Start DUT")
            ble_dut_address = ble_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, "failed to initiate ble in dut"
            logger().info(f"Configuring Remote LE device in Undirected connectable advertising mode")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address,
                hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                               "0x40 0x00 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x00 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00"  # Advertising_Filter_Policy
                , scan_resp_name_params="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                        "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                        "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                        "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
            )
            assert ble_client_address, "failed to initiate ble in remote device"

            logger().info("Start scanning and connect to ble client")
            ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=60)
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")

            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            ble_dut.interfaces.wifi.ble_scanning = False
            ble_dut.interfaces.wifi.ble_advertising = False
            logger().info(f"Initiating ble connection...")
            ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=60)
            logger().info(f"Ble connection is successful")

            logger().info("Check connection status of BLE")
            status = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(status) if status.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            time.sleep(120)

            logger().info("Check connection status of BLE")
            status = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(status) if status.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            logger().info("DUT is not disconnected from BLE")

            logger().info(f"Initiating BLE disconnection from raspi")
            ble_client.interfaces.bluetooth.disconnect(ble_dut_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_undirected_discon_verification_c19836(ble_dut, ble_client, sl_collections):
    """
    Verify BLE connect disconnect functionality
    :param ble_dut:  Fixture parameter to issue command in DUT
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_undirected_discon_verification_c19836.logs_{int(time.time())}"):
            logger().info(f"Start DUT")
            ble_dut_address = ble_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, "failed to initiate ble in dut"
            logger().info(f"Configuring Remote LE device in Undirected connectable advertising mode")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address,
                hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                               "0x40 0x00 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x00 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00"  # Advertising_Filter_Policy
                , scan_resp_name_params="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                        "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                        "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                        "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
            )
            assert ble_client_address, "failed to initiate ble in remote device"

            ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=60)
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")

            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            ble_dut.interfaces.wifi.ble_scanning = False
            ble_dut.interfaces.wifi.ble_advertising = False
            logger().info(f"Initiating ble connection...")
            ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=60)
            logger().info(f"Ble connection is successful")

            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            logger().info(f"Ble connection is successful")
            time.sleep(120)

            logger().info("Check connection status of BLE")
            status = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(status) if status.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            logger().info("DUT is not disconnected from BLE")

            logger().info(f"Initiating BLE disconnection from DUT")
            ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_active_scanning_on_dut_C19837(ble_dut, ble_client, sl_collections):
    """
    Configure DUT_BLE for Active scan and verify its functionality
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
            bt_log_path=f"./test_ble_sdk_active_scanning_on_dut_C19837.logs_{int(time.time())}"):
            logger().info(f"Start DUT")
            ble_dut_address = ble_dut.interfaces.wifi.ble_start()

            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address, "Unable to get ble_client_address"

            logger().info(f"\n\n Start scanning and connect to ble client \n\n")
            ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address,
                                                       ble_scan_type=1, timeout=60)
            time.sleep(60)

            logger().info(f"\n\n ****Enabling Wlan and BLE power save**** \n\n")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info(f"Stopping ble-client advertising")
            ble_client.interfaces.bluetooth.stop_advertising()
            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(5)
            ble_client.interfaces.bluetooth.close()
            time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scanning_on_dut_C19838(ble_dut, ble_client, sl_collections):
    """
    Configure DUT_BLE for Passive scan and verify its functionality
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
            bt_log_path=f"./test_ble_sdk_passive_scanning_on_dut_C19838.logs_{int(time.time())}"):
            logger().info(f"Start DUT")
            ble_dut_address = ble_dut.interfaces.wifi.ble_start()

            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address, "Unable to get ble_client_address"

            logger().info(f"\n\n Start scanning and connect to ble client \n\n")
            ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address,
                                                       ble_scan_type=0, timeout=120)
            time.sleep(20)

            logger().info(f"\n\n ****Enabling Wlan and BLE power save**** \n\n")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info(f"Stopping ble-client advertising")
            ble_client.interfaces.bluetooth.stop_advertising()
            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(5)
            ble_client.interfaces.bluetooth.close()
            time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable", "ble_disconnect"])
def test_ble_sdk_scan_in_advertising_state_C19839(ble_dut, ble_clients, sl_collections):
    """
    Verify BLE Scan in advertising state using 2 RASPI
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_scan_in_advertising_state_C19839.logs_{int(time.time())}"):
            assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
            ble_client1 = ble_clients[1]
            ble_client2 = ble_clients[0]
            logger().info("INITIATING BLE SERVICE IN DUT")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "FAILED TO INITIATE BLE IN DUT"

            logger().info(" **** START ADVERTISING FROM REMOTE DEVICE 1 **** ")
            ble_client_address1 = ble_client1.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address1, "UNABLE TO GET BLE CLIENT ADDRESS"
            logger().info(f"ble_client_address1: {ble_client_address1}")
            time.sleep(5)

            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address1, timeout=120)
            time.sleep(15)
            events = ble_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                    if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                        logger().info(f" event data : {event.event_data}")
                        scan_result = event.event_data

            logger().info(f"SCAN RESULT IS: '{scan_result}")
            assert str(ble_client_address1) in str(
                scan_result), "REMOTE DEVICE 1 ADDRESS ISN'T PRESENT IN DUT SCAN RESULTS"
            logger().info("SUCCESSFULLY FOUND REMOTE DEVICE 1 IN DUT SCAN RESULTS")

            logger().info(" **** START ADVERTISING FROM DUT **** ")
            ble_dut.interfaces.bluetooth.ble_start_advertising(ble_dir_addr=ble_dut_address)
            time.sleep(5)

            logger().info(" **** START SCANNING DUT FROM REMOTE DEVICE 2 **** ")
            ble_client_address2 = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address2, "FAILED TO INITIATE BLE IN REMOTE DEVICE 2"
            time.sleep(20)
            logger().info(f" **** ble_client_address2: {ble_client_address2} **** ")

            found_devices_list = ble_client2.interfaces.bluetooth.get_devices()
            logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices_list}*****************")
            assert ble_dut.interfaces.bluetooth.ble_address in found_devices_list, "DUT ISN'T LISTED IN SCAN RESULTS"
            logger().info("FOUND DUT BD ADDRESS IN SCAN RESULTS")

            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            time.sleep(5)
            logger().info("DISABLING ADVERTISEMENT AND SCANNING FROM RASPI AND DUT")
            ble_dut.interfaces.wifi.ble_stop_scanning()
            ble_client1.interfaces.bluetooth.stop_advertising()
            ble_client2.interfaces.bluetooth.stop_scanning()
            ble_dut.interfaces.wifi.ble_stop_advertising()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


'''Dependent JIRA WIFI_BT_UTFHELP-3422'''
@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC |
                        Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                        Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dut_slave_128_bit_uuid_c19847(ble_dut, ble_client, sl_collections):
    """
    Verify BLE 128 BIT UUID when module as slave
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        set_local_name = "BLE_GAP_TESTPLAN"
        logger().info(f"Setting BLE local name {set_local_name}")
        ble_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = ble_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"getting the local name : {status}")

        logger().info("set dut in adv mode...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        ble_dut.interfaces.bluetooth.ble_uuid_32bit_to_128bit()
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        logger().info("start ble scan from remote le device...")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()

        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices
        assert (
                found_devices[ble_dut.interfaces.wifi.ble_address]
                == ble_dut.interfaces.bluetooth.ble_advertising_data
        )
        logger().info("connect to dut from remote le device....")
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        assert ble_dut_address, "unable to connect to the given address"
        time.sleep(30)

        ble_dut.interfaces.bluetooth.ble_advertising = False

        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        logger().info(f"servs: {servs} \n chars:{chars}")
        service_uid = "00001801-0000-1000-8000-00805f9b34fb"
        char_uid = "0000-aabb-0000-1000-8000-0026bb765291"

        ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs, service_uid=service_uid,
                                                                            char_uid=char_uid)
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"state_int==============>>,  {state_int}")
        if state_int > 0:
            logger().info("disconnecting the dut..")
            ble_client.interfaces.bluetooth.disconnect(ble_dut_address)

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_adv_report_C19848(ble_dut, ble_client, sl_collections):
    """
    Verify Ble Advertise report
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        scan_result = ""
        logger().info("start ble...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info("start ble client...")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        time.sleep(1)
        assert ble_client_address, "failed to initiate ble in remote device"
        logger().info(f"ble client add..{ble_client_address}")
        time.sleep(1)
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(10)
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            events = ble_dut.interfaces.bluetooth.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                    if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                        logger().info(f" event data : {event.event_data}")
                        scan_result = event.event_data
        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        logger().info("verifying client addr, is available in scan list...")
        assert str(ble_client_address) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {ble_client_address}")

        logger().info("stop advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)