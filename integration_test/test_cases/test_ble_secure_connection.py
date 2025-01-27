from utf.utils.logger import get_logger
import time
import pytest
from utf.utils.stopwatch import Stopwatch
import threading
import re
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes


def logger():
    return get_logger(__name__)


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
                                       # Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
def test_ble_smp_sample(wifi_dut, ble_client, pin_code, client_capability, dut_capability):
    try:

        logger().info("Initiate ble service in DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=dut_capability, set_smp=1)
        assert ble_dut_address, "failed to initiate ble in dut"
        wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=0, smp_auth_req_bonding=1,
                                                  smp_auth_req_mitm=1,
                                                  smp_auth_req_sc=1, smp_max_enc_key_size=16,
                                                  smp_local_oob_data_flag_not_present=0, smp_enc_key=1, smp_id_key=0,
                                                  smp_sign_key=0)
        # wifi_dut.interfaces.wifi.bt_set_local_name("BLE_UNIFIED_DEMO")
        wifi_dut.interfaces.wifi.ble_start_advertising()

        # Set BLE client security settings
        logger().info("Set MITM and security requirements in BLE client")

        # Set MITM and SC bits
        """
        Parameters:
        < IO Capability >: Specifies the IO capability.
        0x00: DisplayOnly
        0x01: Display Yes / No
        0x02: KeyboardOnly
        0x03: NoInput / NoOutput
        0x04: Keyboard / Display

        < OOB Data Flag >: Specifies whether Out - of - Band(OOB) data is used.
        0x00: OOB not used.
        0x01: OOB used.

        < AuthReq >: Authentication requirements.

        Bit 0 (MITM): 0 = No MITM, 1 = MITM required.
        Bit 2 (SC): 0 = Legacy pairing, 1 = Secure Connections.

        MITM	SC	 Value (AuthReq) 	Description
         0	     0	  0x00	      No MITM, Legacy pairing
         1       0	  0x01	      MITM required, Legacy pairing
         0	     1	  0x04	      No MITM, Secure Connections required
         1	     1	  0x05	      MITM required, Secure Connections only

         Example command: hcitool cmd 0x08 0x002e <IO Capability> <OOB Data Flag> <AuthReq>

        """
        ble_client.interfaces.bluetooth.set_mitm_sc_bits("0x02 0x00 0x05 ")  # <IO Capability> <OOB Data Flag> <AuthReq>

        # Start ble client scan
        logger().info("Start smp scan from the remote device")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                            capability=client_capability,
                                                                            pin_code=pin_code)
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)

        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()
        logger().info("Check the dut is listed...")
        ble_client.interfaces.bluetooth.get_devices()

        def connect():
            logger().info("Connect to the dut with mac address..")
            ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)

        t = threading.Thread(target=connect)
        t.start()
        tw = Stopwatch()
        pass_key_found = False

        while tw.elapsed_sec < 30:
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.BLE_SC_PASSKEY:
                    if "passkey" in event.event_data:
                        passkey = re.findall(r"passkey: ([\d]*)", event.event_data)
                        if passkey[0] is not None:
                            pass_key_value = str(passkey[0])
                            logger().info(f"passkey : {pass_key_value}")
                            ble_client.interfaces.bluetooth.set_pin(pass_key_value)
                            pass_key_found = True
                            break

            if pass_key_found:
                break

            time.sleep(1)

        time.sleep(10)

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    except Exception as error:
        logger().error(f"error : {error}")

    finally:
        if t is not None:
            t.join()
