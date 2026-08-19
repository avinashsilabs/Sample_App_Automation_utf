import os
import time
import threading
import datetime
from pathlib import Path
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
import re
import pytest
import subprocess
import urllib.request
import urllib.error

"""
    * setup requirement:
        1. DUT(RS9116) B00 board
        2. RT595 Host Board
        3. Teledyne sniffer (to capture BLE OTA logs)
        4. NUC as Remote device
        5. Ellysis (to Capture OTA logs) - optional
    Test Coverage:
        - Verifying the Complete AG Functionalities
        - Including the Call Control functionalities
    Author: 
        Lenin Kale
"""

def logger():
    return get_logger(__name__)


class BLESMPPairingTest:
    """
    BLE Security Manager Protocol (SMP) Pairing Test Handler

    This class manages the complete BLE pairing process between a DUT (peripheral)
    and a Raspberry Pi (central) with configurable IO capabilities and authentication
    requirements.

    Attributes:
        wifi_dut: DUT device interface
        ble_client: Raspberry Pi BLE client interface
        dut_capability: IO capability of the DUT (DisplayOnly, KeyboardOnly, etc.)
        client_capability: IO capability of the Raspberry Pi client
        pin_code: PIN code for pairing
        oob_data_flag: Out-of-Band data flag (0x00 = not present, 0x01 = present)
    """
    
    def __init__(self, wifi_dut, ble_client, dut_capability, client_capability, pin_code, smp_sc=0, smp_auth_bond=1,
                 smp_mtim=1, smp_enc_key=1, passkey_state=2, random_addr_on_dut=False, auth_req="0x05", test_case_id=None,
                 oob_data_flag="0x00"):
                 
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.dut_capability = dut_capability
        self.client_capability = client_capability
        self.pin_code = pin_code
        self.smp_sc = smp_sc
        self.smp_auth_bond = smp_auth_bond
        self.smp_mtim = smp_mtim
        self.smp_enc_key = smp_enc_key
        self.passkey_state = passkey_state
        self.random_addr_on_dut = random_addr_on_dut
        self.auth_req = auth_req
        self.ble_dut_address = None
        self.ble_client_address = None
        self.connection_successful = False
        self.pairing_successful = False
        self.last_bt_disconnect_reason = None
        self.test_case_id = test_case_id
        self.stop_audio_event = threading.Event()
        self.audio_thread = None
        self.audio_loop_active = False

    def check_expected_event(
        self,
        expected_event,
        action="CLI command",
        timeout_sec=5,
        poll_interval_sec=0.1,
    ):
        """Assert that a DUT serial event is received after a CLI command."""
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        deadline = time.monotonic() + timeout_sec
        log_text = ""

        while True:
            input_log = serial_conn.get_input_log()
            log_text = "\n".join(
                line.decode(errors="ignore")
                if isinstance(line, (bytes, bytearray))
                else str(line)
                for _, line in input_log
            )
            if expected_event in log_text:
                logger().info(f"PASS: Observed '{expected_event}' after {action}")
                return
            if time.monotonic() >= deadline:
                break
            time.sleep(poll_interval_sec)

        assert expected_event in log_text, (
            f"TestCase {self.test_case_id}: expected DUT serial event "
            f"'{expected_event}' after {action}, but it was not found "
            f"within {timeout_sec} seconds."
        )

    def start_hfp_audio(self):
        media_server_url = os.environ.get("WINDOWS_MEDIA_SERVER_URL")
        if not media_server_url:
            raise RuntimeError(
                "WINDOWS_MEDIA_SERVER_URL is not configured. Set it to the "
                "Windows Media Player service URL, for example "
                "http://<windows-host-ip>:5000."
            )
        try:
            response = urllib.request.urlopen(
                f"{media_server_url.rstrip('/')}/play",
                timeout=20
            )
            response_body = response.read().decode()
            if response.status != 200:
                raise RuntimeError(
                    f"Windows Media Player service rejected playback: "
                    f"HTTP {response.status}: {response_body}"
                )
            logger().info(f"Windows Media Player started: {response_body}")
        except urllib.error.HTTPError as e:
            response_body = e.read().decode(errors="replace")
            raise RuntimeError(
                f"Windows Media Player service rejected playback: "
                f"HTTP {e.code}: {response_body}"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Failed to start Windows Media Player: {e}") from e

    def stop_hfp_audio(self):
        media_server_url = os.environ.get("WINDOWS_MEDIA_SERVER_URL")
        if not media_server_url:
            logger().warning(
                "WINDOWS_MEDIA_SERVER_URL is not configured; cannot stop "
                "Windows Media Player through the media service"
            )
            return
        try:
            response = urllib.request.urlopen(
                f"{media_server_url.rstrip('/')}/stop",
                timeout=15
            )
            response_body = response.read().decode()
            if response.status != 200:
                logger().warning(
                    f"Windows Media Player service rejected stop: "
                    f"HTTP {response.status}: {response_body}"
                )
                return
            logger().info(f"Windows Media Player stopped: {response_body}")
        except Exception as e:
            logger().warning(f"Failed to stop Windows Media Player: {e}")
    def run(self):
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03,
                         "KeyboardDisplay": 0x04}

        # Determine pairing method and auth_req based on IO capabilities
        dut_io = io_capability[self.dut_capability]
        client_io = io_capability[self.client_capability]

        # JustWorks scenarios (no MITM protection possible - use auth_req=0x01)
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        justworks_scenarios = [
            (0x00, 0x00),  # DisplayOnly + DisplayOnly
            (0x00, 0x01),  # DisplayOnly + DisplayYesNo
            (0x00, 0x03),  # DisplayOnly + NoInputNoOutput
            (0x01, 0x00),  # DisplayYesNo + DisplayOnly
            (0x01, 0x03),  # DisplayYesNo + NoInputNoOutput
            (0x02, 0x03),  # KeyboardOnly + NoInputNoOutput
            (0x03, 0x00),  # NoInputNoOutput + DisplayOnly
            (0x03, 0x03),  # NoInputNoOutput + NoInputNoOutput
            (0x03, 0x01),  # NoInputNoOutput + DisplayYesNo
            (0x03, 0x04),  # NoInputNoOutput + KeyboardDisplay
            (0x03, 0x02),  # NoInputNoOutput + KeyboardOnly
            (0x04, 0x03),  # KeyboardDisplay + NoInputNoOutput
        ]

        # Numeric Comparison scenarios (both devices display passkey, both need to confirm/enter)
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        numeric_comparison_scenarios = [
            (0x01, 0x01),  # DisplayYesNo + DisplayYesNo
            (0x01, 0x04),  # DisplayYesNo + KeyboardDisplay
            (0x04, 0x01),  # KeyboardDisplay + DisplayYesNo
            (0x04, 0x04),  # KeyboardDisplay + KeyboardDisplay
        ]

        # Passkey Entry scenarios - Responder (DUT) DISPLAYS, Initiator (Raspi) ENTERS
        # The DUT generates and displays the passkey, Raspi must enter it
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        passkey_responder_displays_scenarios = [
            (0x00, 0x02),  # DisplayOnly + KeyboardOnly -> DUT displays, Raspi enters
            (0x00, 0x04),  # DisplayOnly + KeyboardDisplay -> DUT displays, Raspi enters
            (0x01, 0x02),  # DisplayYesNo + KeyboardOnly -> DUT displays, Raspi enters
            (0x04, 0x02),  # KeyboardDisplay + KeyboardOnly -> DUT displays, Raspi enters
            (0x02, 0x02),
            # KeyboardOnly + KeyboardOnly -> DUT displays, Raspi enters (though this may also be Numeric Comparison in some implementations
        ]

        # Passkey Entry scenarios - Initiator (Raspi) DISPLAYS, Responder (DUT) ENTERS
        # The Raspi generates and displays the passkey, DUT must enter it
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        passkey_initiator_displays_scenarios = [
            (0x02, 0x00),  # KeyboardOnly + DisplayOnly -> Raspi displays, DUT enters
            (0x02, 0x01),  # KeyboardOnly + DisplayYesNo -> Raspi displays, DUT enters
            (0x02, 0x04),  # KeyboardOnly + KeyboardDisplay -> Raspi displays, DUT enters
            (0x04, 0x00),  # KeyboardDisplay + DisplayOnly -> Raspi displays, DUT enters

        ]

        # Determine pairing method and passkey direction
        if (dut_io, client_io) in justworks_scenarios:
            pairing_method = "JustWorks"
            passkey_direction = None
            auth_req_value = 0x09  # Bonding + SC (no MITM) - prevents Raspi disconnect
        elif (dut_io, client_io) in numeric_comparison_scenarios:
            pairing_method = "NumericComparison"
            passkey_direction = "both"  # Both devices display and need confirmation/entry
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        elif (dut_io, client_io) in passkey_responder_displays_scenarios:
            pairing_method = "PasskeyEntry"
            passkey_direction = "dut_displays"  # DUT (responder) displays, Raspi (initiator) enters
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        elif (dut_io, client_io) in passkey_initiator_displays_scenarios:
            pairing_method = "PasskeyEntry"
            passkey_direction = "raspi_displays"  # Raspi (initiator) displays, DUT (responder) enters
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        else:
            # Fallback - should not reach here if all scenarios are covered
            pairing_method = "PasskeyEntry"
            passkey_direction = "dut_displays"  # Default: DUT displays
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)

        if pairing_method in ("JustWorks", "NumericComparison"):
            nuc_capability = self.client_capability
            nuc_pin_code = "0"
        elif pairing_method == "PasskeyEntry" and passkey_direction == "dut_displays":
            nuc_capability = "KeyboardOnly"
            nuc_pin_code = "-8"
        else:
            nuc_capability = self.client_capability
            nuc_pin_code = "0"

        # ======================================================================
        logger().info("=" * 80)
        logger().info("STEP 1: NUC - Start BT Classic Advertising (discoverable + pairable)")
        logger().info("=" * 80)

        try:
            logger().info("Getting DUT local address...")
            # time.sleep(20)
            self.dut_address = self.wifi_dut.interfaces.wifi.get_local_address()
            logger().info(f"DUT address: {self.dut_address}")

            logger().info("Starting BLE advertising on NUC...")
            self.nuc_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.dut_address,
                capability=nuc_capability,
                pin_code=nuc_pin_code,
                restart_bt_service=False,
            )
            logger().info(f"✓ PASS: NUC advertising started, address: {self.nuc_address}")
            time.sleep(3)

        except Exception as e:
            logger().error(f"✗ FAIL: Failed to start NUC advertising: {e}")
            assert False, f"NUC advertising failed: {e}"

        # ======================================================================
        logger().info("=" * 80)
        logger().info("STEP 2: DUT - Connect to NUC via BT Classic CLI")
        logger().info("=" * 80)
        time.sleep(5)

        data_src_result = self.wifi_dut.interfaces.wifi.btc_a2dp_audio_data_src_selection(src=1)
        logger().info("A2DP audio data src selection command sent (btc a2dp a2dp_audio_data_src_selection 1)")
        time.sleep(2)
        assert data_src_result, "A2DP audio data src selection failed"

        connect_result = self.wifi_dut.interfaces.wifi.bt_connect(self.nuc_address)
        logger().info("bt_connect command issued; waiting for authentication/profile events.")
        logger().info(f"bt_connect returned: {connect_result!r}")
        time.sleep(10)
        assert connect_result, "BT connection failed"

        logger().info("=" * 80)
        avrcp_pause_result = self.wifi_dut.interfaces.wifi.bt_avrcp_pause(bt_address=self.nuc_address)
        logger().info(f"AVRCP pause command sent (btc avrcp avrcp_pause {self.nuc_address})")
        time.sleep(2)
        assert avrcp_pause_result, "AVRCP pause failed"

        # C554021: verify HF features from live serial log after connection
        if self.test_case_id == "C554021":
            try:
                serial_conn = self.wifi_dut.interfaces.wifi.bus
                input_log = serial_conn.get_input_log()
                log_text = "\n".join(
                    line.decode(errors="ignore") if isinstance(line, (bytes, bytearray)) else str(line)
                    for _, line in input_log
                )
                expected_hf_features = [
                    "ECNR",
                    "Three Way Calling",
                    "CLI Capability",
                    "Voice_Recognition",
                    "Remote Volume Control",
                    "EnhancedCallSts",
                    "EnhancedCallCtrl",
                    "CodecNegot",
                    "HFIndicators",
                    "MSBC Supported",
                    "CVSD Supported",
                ]
                unsupported = []
                missing = []
                for feature_name in expected_hf_features:
                    supported = f"{feature_name} = SUPPORTED"
                    not_supported = f"{feature_name} = NOT_SUPPORTED"
                    if not_supported in log_text:
                        unsupported.append(feature_name)
                    elif supported not in log_text:
                        missing.append(feature_name)
                    else:
                        logger().info(f"TestCase {self.test_case_id} ✓ PASS: {supported} after connection")
                if unsupported:
                    raise RuntimeError(
                        "HF feature(s) reported as NOT_SUPPORTED after connection: "
                        + ", ".join(unsupported)
                    )
                if missing:
                    raise RuntimeError(
                        "HF feature(s) not found as SUPPORTED in DUT serial log after connection: "
                        + ", ".join(missing)
                    )
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554022":
            try:
                self.ble_client.interfaces.bluetooth.disconnect(
                    dev_addr=self.dut_address)
                logger().info(f"TestCase {self.test_case_id} ✓ PASS: DUT disconnected from NUC")
                self.check_expected_event(
                    f"disconn {self.nuc_address},0x4e13",
                    action="HF disconnect",
                )
                time.sleep(3)
            except Exception as e:
                raise RuntimeError(
                    f"TestCase {self.test_case_id}: DUT is not disconnected from NUC: {e}"
                ) from e  
            finally:
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554023":
            try:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info(f"TestCase {self.test_case_id} ✓ PASS: NUC disconnected from DUT")
                time.sleep(3)
                self.check_expected_event(
                    f"A2DP Source disconnect event: {self.nuc_address}",
                    action="AG disconnect",
                )
            except Exception as e:
                raise RuntimeError(
                    f"TestCase {self.test_case_id}: NUC is not disconnected from DUT: {e}"
                ) from e
            finally:
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554024":
            try:
                logger().info(f"Disconnecting HFP from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_hfp_disconnect(bt_address=self.nuc_address)
                logger().info("HFP disconnect command sent (btc hfp hfp_test_bench)")
                self.check_expected_event(
                    f"hfp disconn AG:{self.nuc_address}",
                    action="btc hfp hfp_test_bench",
                )
                time.sleep(3)
            except Exception as e:
                raise RuntimeError(
                    f"TestCase {self.test_case_id}: HFP is not disconnected from DUT: {e}"
                ) from e
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554025":
            try:
                logger().info(f"Disabling AG inband ringtone from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_disable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone disable command sent (btc hfp ag_inband_ringtone)")
                time.sleep(3)
                self.check_expected_event(
                    f"AG Inband Ringtone DISABLE",
                    action="btc hfp ag_inband_ringtone disable",
                )
            except Exception as e:
                raise RuntimeError(
                    f"TestCase {self.test_case_id}: AG inband ringtone is not disabled from DUT: {e}"
                ) from e
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554026":
            try:
                logger().info(f"Enabling AG inband ringtone from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_enable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone enable command sent (btc hfp ag_inband_ringtone)")
                time.sleep(3)
                self.check_expected_event(
                    f"AG Inband Ringtone ENABLE",
                    action="btc hfp ag_inband_ringtone enable",
                )
            except Exception as e:
                raise RuntimeError(
                    f"TestCase {self.test_case_id}: AG inband ringtone is not enabled from DUT: {e}"
                ) from e
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554027":
            try:
                logger().info(f"Enabling wrong AG inband ringtone from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_wrong_inband_ringtone_enable(bt_address=self.nuc_address)
                logger().info("AG wrong inband ringtone enable command sent (btc hfp ag_inband_ringtone)")
                time.sleep(3)
                expected_message = "HFP Indband status change err 0xb"
                serial_conn = self.wifi_dut.interfaces.wifi.bus
                log_text = ""
                for _ in range(20):
                    input_log = serial_conn.get_input_log()
                    log_text = "\n".join(
                        line.decode(errors="ignore")
                        if isinstance(line, (bytes, bytearray))
                        else str(line)
                        for _, line in input_log
                    )
                    if expected_message in log_text:
                        break
                    time.sleep(0.1)

                assert expected_message in log_text, (
                    f"TestCase {self.test_case_id}: expected DUT message "
                    f"'{expected_message}' was not received after "
                    f"'btc hfp ag_inband_ringtone {self.nuc_address} 2'."
                )
                logger().info(
                    f"TestCase {self.test_case_id} ✓ PASS: received "
                    f"'{expected_message}'"
                )

            except Exception as e:
                raise RuntimeError(
                    f"TestCase {self.test_case_id}: AG wrong inband ringtone is not enabled from DUT: {e}"
                ) from e
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)

        if self.test_case_id == "C554028":
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"AG call establish failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554029":
            media_player_started = False
            try:
                logger().info(f"Disabling AG inband ringtone from DUT ({self.nuc_address})...")
                inband_ringtone_disable_result = self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_disable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone disable command sent (btc hfp ag_inband_ringtone)")
                self.check_expected_event(
                    f"AG Inband Ringtone DISABLE",
                    action="btc hfp ag_inband_ringtone disable",
                )
                time.sleep(3)
                assert inband_ringtone_disable_result, "AG inband ringtone disable failed"

                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                time.sleep(3)
                assert result_1, "AG call establish failed"
                assert result_2, "AG call establish failed"
                assert result_3, "AG call establish failed"

                logger().info(f"Accepting AG call from NUC ({self.nuc_address})...")
                call_accept_result = self.wifi_dut.interfaces.wifi.bt_ag_call_accept(bt_address=self.nuc_address)
                logger().info("AG call accept command sent (btc hfp ag_call_accept)")
                self.check_expected_event(
                    f"AG call active",
                    action=f"btc hfp ag_call_accept : {self.nuc_address}",
                )
                assert call_accept_result, "AG call accept failed"
                time.sleep(3)

                logger().info("Starting Windows Media Player because HFP call is active")
                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)

                logger().info(f"Terminating AG call to NUC ({self.nuc_address})...")
                call_terminate_result = self.wifi_dut.interfaces.wifi.bt_ag_call_terminate(bt_address=self.nuc_address)
                logger().info("AG call terminate command sent (btc hfp ag_call_terminate)")
                self.check_expected_event(
                    f"AG call end",
                    action=f"btc hfp ag_call_terminate : {self.nuc_address}",
                )
                assert call_terminate_result, "AG call terminate failed"
                time.sleep(3)

            except Exception as e:
                assert False, f"AG call establish failed: {e}"
            finally:
                # Stop Windows Media Player only after call termination, or
                # during cleanup if call setup/termination failed.
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554030":
            media_player_started = False
            try:
                logger().info(f"Disabling AG inband ringtone from DUT ({self.nuc_address})...")
                inband_ringtone_enable_result = self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_enable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone enable command sent (btc hfp ag_inband_ringtone)")
                self.check_expected_event(
                    f"AG Inband Ringtone ENABLE",
                    action="btc hfp ag_inband_ringtone enable 1",
                )
                assert inband_ringtone_enable_result, "AG inband ringtone enable failed"
                time.sleep(3)

                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                assert result_1, "AG call establish failed"
                assert result_2, "AG call establish failed"
                assert result_3, "AG call establish failed"
                time.sleep(3)

                logger().info(f"Accepting AG call from NUC ({self.nuc_address})...")
                call_accept_result = self.wifi_dut.interfaces.wifi.bt_ag_call_accept(bt_address=self.nuc_address)
                logger().info("AG call accept command sent (btc hfp ag_call_accept)")
                self.check_expected_event(
                    f"AG call active",
                    action=f"btc hfp ag_call_accept : {self.nuc_address}",
                )
                assert call_accept_result, "AG call accept failed"
                time.sleep(3)

                logger().info("Starting Windows Media Player because HFP call is active")
                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)
                
                logger().info(f"Terminating AG call to NUC ({self.nuc_address})...")
                call_terminate_result = self.wifi_dut.interfaces.wifi.bt_ag_call_terminate(bt_address=self.nuc_address)
                self.check_expected_event(
                    f"AG call end",
                    action=f"btc hfp ag_call_terminate : {self.nuc_address}",
                )
                assert call_terminate_result, "AG call terminate failed"
                logger().info("AG call terminate command sent (btc hfp ag_call_terminate)")
                time.sleep(3)
            except Exception as e:
                assert False, f"AG call establish failed: {e}"
            finally:
                # Stop Windows Media Player only after call termination, or
                # during cleanup if call setup/termination failed.
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554031":
            media_player_started = False
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",   
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                assert result_1, "AG call establish failed"
                assert result_2, "AG call establish failed"
                assert result_3, "AG call establish failed"
                time.sleep(3)

                logger().info(f"Disabling AG inband ringtone from DUT ({self.nuc_address})...")
                inband_ringtone_enable_result = self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_enable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone enable command sent (btc hfp ag_inband_ringtone)")
                self.check_expected_event(
                    f"AG Inband Ringtone ENABLE",
                    action="btc hfp ag_inband_ringtone enable 1",
                )
                assert inband_ringtone_enable_result, "AG inband ringtone enable failed"
                time.sleep(3)

                logger().info(f"Accepting AG call from NUC ({self.nuc_address})...")
                call_accept_result = self.wifi_dut.interfaces.wifi.bt_ag_call_accept(bt_address=self.nuc_address)
                logger().info("AG call accept command sent (btc hfp ag_call_accept)")
                self.check_expected_event(
                    f"AG call active",
                    action=f"btc hfp ag_call_accept : {self.nuc_address}",
                )
                logger().info("Starting Windows Media Player because HFP call is active")
                assert call_accept_result, "AG call accept failed"
                time.sleep(3)

                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)
                
                logger().info(f"Terminating AG call to NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_terminate(bt_address=self.nuc_address)
                logger().info("AG call terminate command sent (btc hfp ag_call_terminate)")
                self.check_expected_event(
                    f"AG call end",
                    action=f"btc hfp ag_call_terminate : {self.nuc_address}",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"AG call establish failed: {e}"
            finally:
                # Stop Windows Media Player only after call termination, or
                # during cleanup if call setup/termination failed.
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554037":
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                time.sleep(3)
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                logger().info(f"Rejecting AG call from NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_reject(bt_address=self.nuc_address)
                logger().info("AG call reject command sent (btc hfp ag_call_reject)")
                self.check_expected_event(
                    f"AG call rej",
                    action=f"btc hfp ag_call_reject : {self.nuc_address}",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"AG call reject failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554039":
            media_player_started = False
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_outgoing_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_OUTGOING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:ALERT",
                    action="btc hfp ag_call_establish 3",  
                )
                time.sleep(3)
                logger().info(f"Accepting AG call from NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_accept(bt_address=self.nuc_address)
                logger().info("AG call accept command sent (btc hfp ag_call_accept)")
                self.check_expected_event(
                    f"AG call active",
                    action=f"btc hfp ag_call_accept : {self.nuc_address}",
                )
                time.sleep(3)
                logger().info("Starting Windows Media Player because HFP call is active")
                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)

                logger().info(f"Terminating AG call to NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_terminate(bt_address=self.nuc_address)
                logger().info("AG call terminate command sent (btc hfp ag_call_terminate)")
                self.check_expected_event(
                    f"AG call end",
                    action=f"btc hfp ag_call_terminate : {self.nuc_address}",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"AG outgoing call establish failed: {e}"
            finally:
                # Stop Windows Media Player only after call termination, or
                # during cleanup if call setup/termination failed.
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554042":
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_outgoing_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_OUTGOING",
                    action="btc hfp ag_call_establish 4",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:ALERT",
                    action="btc hfp ag_call_establish 5",  
                )
                time.sleep(20)

                logger().info(f"Terminating AG call to NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_terminate(bt_address=self.nuc_address)
                logger().info("AG call terminate command sent (btc hfp ag_call_terminate)")
                self.check_expected_event(
                    f"AG call end",
                    action=f"btc hfp ag_call_terminate : {self.nuc_address}",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"AG call terminate failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554043":
            try:
                logger().info(f"VR Activating on NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_vr_activate(bt_address=self.nuc_address)
                logger().info("AG call vr activate command sent (btc hfp ag_call_vr_activate)")
                self.check_expected_event(
                    f"hfp audio conn:{self.nuc_address}",
                    action=f"btc hfp ag_call_vr_activate : {self.nuc_address}",
                )
                time.sleep(3)
                
                #This is combined test case, so we need to deactivate the VR after the activation
                logger().info(f"VR Deactivating on NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_vr_deactivate(bt_address=self.nuc_address)
                logger().info("AG call vr deactivate command sent (btc hfp ag_call_vr_deactivate)")
                self.check_expected_event(
                    f"hfp audio disconn:{self.nuc_address}",
                    action=f"btc hfp ag_call_vr_deactivate : {self.nuc_address}",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"AG call vr activate failed: {e}"
                assert False, f"AG call vr deactivate failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)

        if self.test_case_id == "C554032":
            media_player_started = False
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                time.sleep(3)

                logger().info(f"Accepting AG call from DUT ({self.dut_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_accept(bt_address=self.nuc_address)
                logger().info("AG call accept command sent (btc hfp ag_call_accept)")
                self.check_expected_event(
                    f"AG call active",
                    action=f"btc hfp ag_call_accept : {self.nuc_address}",
                )
                logger().info("Starting Windows Media Player because HFP call is active")
                time.sleep(3)

                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)
                
                logger().info(f"Terminating Active call from NUC ({self.nuc_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.hangup_hfp_call(
                    dev_addr=self.dut_address
                )
                assert hangup_success, "oFono VoiceCall Hangup failed"
                logger().info("Terminated Active call from NUC")
                time.sleep(3)
            except Exception as e:
                assert False, f"Active call hangup failed: {e}"
            finally:
                # Stop Windows Media Player only after call termination, or
                # during cleanup if call setup/termination failed.
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554033":
            media_player_started = False
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                time.sleep(3)

                logger().info(f"Accepting incoming call from DUT ({self.dut_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.answer_hfp_call(
                    dev_addr=self.dut_address
                )
                assert hangup_success, "oFono VoiceCall Accept failed"
                logger().info("Accepted incoming call from DUT")
                time.sleep(3)

                logger().info("Starting Windows Media Player because HFP call is active")
                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)

                logger().info(f"Terminating AG call to NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_terminate(bt_address=self.nuc_address)
                logger().info("AG call terminate command sent (btc hfp ag_call_terminate)")
                self.check_expected_event(
                    f"AG call end",
                    action=f"btc hfp ag_call_terminate : {self.nuc_address}",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"Incoming call accept failed: {e}"
            finally:
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554034":
            media_player_started = False
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                time.sleep(3)

                logger().info(f"Accepting incoming call from DUT ({self.dut_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.answer_hfp_call(
                    dev_addr=self.dut_address
                )
                logger().info(f"VoiceCall Accept result: {hangup_success!r}")
                assert hangup_success, "oFono VoiceCall Accept failed"
                logger().info("Accepted incoming call from DUT")
                time.sleep(3)
                
                logger().info("Starting Windows Media Player because HFP call is active")
                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)

                logger().info(f"Terminating Active call from NUC ({self.nuc_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.hangup_hfp_call(
                    dev_addr=self.dut_address
                )
                assert hangup_success, "oFono VoiceCall Hangup failed"
                logger().info("Terminated Active call from NUC")
                time.sleep(3)
            except Exception as e:
                assert False, f"Active call hangup failed: {e}"
            finally:
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554035":
            try:
                logger().info(f"Enabling AG inband ringtone from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_enable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone enable command sent (btc hfp ag_inband_ringtone)")
                self.check_expected_event(
                    f"AG Inband Ringtone ENABLE",
                    action="btc hfp ag_inband_ringtone enable 1",
                )
                time.sleep(3)
    
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                time.sleep(30)

                logger().info(f"Terminating Active call from NUC ({self.nuc_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.hangup_hfp_call(
                    dev_addr=self.dut_address
                )
                assert hangup_success, "oFono VoiceCall Hangup failed"
                logger().info("Terminated Active call from NUC")
                time.sleep(3)
            except Exception as e:
                assert False, f"Active call hangup failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554036":
            try:
                logger().info(f"Enabling AG inband ringtone from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_disable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone disable command sent (btc hfp ag_inband_ringtone)")
                self.check_expected_event(
                    f"AG Inband Ringtone DISABLE",
                    action="btc hfp ag_inband_ringtone disable 1",
                )
                time.sleep(3)
            
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                time.sleep(30)

                logger().info(f"Terminating Active call from NUC ({self.nuc_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.hangup_hfp_call(
                    dev_addr=self.dut_address
                )
                assert hangup_success, "oFono VoiceCall Hangup failed"
                logger().info("Terminated Active call from NUC")
                time.sleep(3)
            except Exception as e:
                assert False, f"Active call hangup failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554038":
            try:
                logger().info(f"Enabling AG inband ringtone from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_inband_ringtone_disable(bt_address=self.nuc_address)
                logger().info("AG inband ringtone disable command sent (btc hfp ag_inband_ringtone)")
                self.check_expected_event(
                    f"AG Inband Ringtone DISABLE",
                    action="btc hfp ag_inband_ringtone disable 1",
                )
                time.sleep(3)   
            
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_INCOMING",
                    action="btc hfp ag_call_establish 1",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 2",
                )
                self.check_expected_event(
                    f"AG call:RING",
                    action="btc hfp ag_call_establish 3",  
                )
                time.sleep(30)

                logger().info(f"Rejecting AG call from NUC ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_reject(bt_address=self.nuc_address)
                logger().info("AG call reject command sent (btc hfp ag_call_reject)")
                self.check_expected_event(
                    f"AG call rej",
                    action=f"btc hfp ag_call_reject : {self.nuc_address}",
                )
                time.sleep(3)
            except Exception as e:
                assert False, f"AG call reject failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554040":
            media_player_started = False
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_outgoing_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_OUTGOING",
                    action="btc hfp ag_call_establish 4",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 5",
                )
                self.check_expected_event(
                    f"AG call:ALERT",
                    action="btc hfp ag_call_establish 5",  
                )
                time.sleep(3)

                logger().info(f"Accepting AG call from DUT ({self.nuc_address})...")
                self.wifi_dut.interfaces.wifi.bt_ag_call_accept(bt_address=self.nuc_address)
                logger().info("AG call accept command sent (btc hfp ag_call_accept)")
                self.check_expected_event(
                    f"AG call active",
                    action=f"btc hfp ag_call_accept : {self.nuc_address}",
                )
                time.sleep(3)

                logger().info("Starting Windows Media Player because HFP call is active")
                self.start_hfp_audio()
                media_player_started = True
                logger().info(
                    "Windows Media Player is looping audio until the HFP call ends"
                )
                time.sleep(120)

                logger().info(f"Terminating Active call from NUC ({self.nuc_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.hangup_hfp_call(
                    dev_addr=self.dut_address
                )
                assert hangup_success, "oFono VoiceCall Hangup failed"
                logger().info("Terminated Active call from NUC")
                time.sleep(3)
            except Exception as e:
                assert False, f"Active call hangup failed: {e}"
            finally:
                # Stop Windows Media Player only after call termination, or
                # during cleanup if call setup/termination failed.
                if media_player_started:
                    self.stop_hfp_audio()
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)
        if self.test_case_id == "C554041":
            try:
                logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
                result_1, result_2, result_3 = self.wifi_dut.interfaces.wifi.bt_ag_outgoing_call_establish(
                    bt_address=self.nuc_address
                )
                logger().info("AG call establish command sent (btc hfp ag_call_establish)")
                logger().info(f"AG call establish results: 1={result_1!r} 2={result_2!r} 3={result_3!r}")
                self.check_expected_event(
                    f"AG callestablish : SETUP_OUTGOING",
                    action="btc hfp ag_call_establish 4",
                )
                self.check_expected_event(
                    f"hfp Codec select : str_conn_bd_addr: {self.nuc_address}, codec_val : 2",
                    action="btc hfp ag_call_establish 5",
                )
                self.check_expected_event(
                    f"AG call:ALERT",
                    action="btc hfp ag_call_establish 5",  
                )
                time.sleep(20)

                logger().info(f"Terminating Active call from NUC ({self.nuc_address})...")
                hangup_success = self.ble_client.interfaces.bluetooth.hangup_hfp_call(
                    dev_addr=self.dut_address
                )
                assert hangup_success, "oFono VoiceCall Hangup failed"
                logger().info("Terminated Active call from NUC")
                time.sleep(3)
            except Exception as e:
                assert False, f"Active call hangup failed: {e}"
            finally:
                self.wifi_dut.interfaces.wifi.bt_disconnect(self.nuc_address)
                logger().info("PASS: bt_disconnect executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.dut_address)
                logger().info("PASS: remove_device executed successfully")
                time.sleep(3)
                self.ble_client.interfaces.bluetooth.close()
                logger().info("PASS: close executed successfully")
                time.sleep(3)

# Just works, Raspi: 0x00 (Display) DUT: 0x00 (Display)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize("test_case_id",["C554024"])
                        # ["C554021","C554022","C554023",
                        # "C554024","C554025"])
 #"C554040","C554041",
@pytest.mark.test_src_map_id('C554024')#,'C554022','C554023','C554024','C554025')

def test_verify_nuc_as_ble_client_ag_C554021_to_C554025(wifi_dut, ble_client,test_case_id,ble_sniffer):
    
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    # Generate unique btmon log filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file = f"reports/ag_test_btmon_NUC_{timestamp}_{test_case_id}.log"
    remote_btmon_log = f"/tmp/btmon_ag_{timestamp}_{test_case_id}.log"

    # Access NUC shell
    nuc_shell = ble_client.interfaces.nuc_host_shell
    btmon_command = None

    # ======================================================================
    # Start btmon on NUC BEFORE the test
    # ======================================================================
    logger().info("=" * 80)
    logger().info(f"Starting btmon on NUC (10.207.20.149)")
    logger().info(f"Remote log: {remote_btmon_log}")
    logger().info("=" * 80)

    try:
        # Kill any existing btmon processes
        nuc_shell.execute("sudo pkill btmon")
        time.sleep(1)

        # Start btmon in background on NUC
        btmon_command = nuc_shell.execute_in_background(
            f"sudo btmon -t > {remote_btmon_log} 2>&1"
        )
        time.sleep(2)  # Give btmon time to start
        logger().info("✓ btmon started on NUC")

    except Exception as e:
        logger().error(f"Failed to start btmon on NUC: {e}")

    # ======================================================================
    # Execute pre-test commands on NUC/BLE client
    # ======================================================================
    logger().info("=" * 80)
    logger().info("Executing pre-test commands on NUC/BLE client...")
    logger().info("=" * 80)

    try:

        # Check Bluetooth status
        rc, stdout, stderr = nuc_shell.execute("hciconfig -a")
        logger().info(f"HCI Config output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pulseaudio -k")
        logger().info(f"Pulseaudio output:\n{stdout}")

        time.sleep(2)

        rc, stdout, stderr = nuc_shell.execute("pulseaudio --start")
        logger().info(f"Pulseaudio output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluez5-discover")
        logger().info(f"pactl bluez5 modules:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluetooth-discover")
        logger().info(f"pactl bluetooth modules:\n{stdout}")

    except Exception as e:
        logger().error(f"Failed to execute pre-test commands on NUC: {e}")
        # Decide if you want to fail the test or continue
        # raise  # Uncomment to fail test on command execution error

    logger().info("Pre-test commands completed")
    logger().info("=" * 80)

    # ======================================================================
    # Run the actual test (btmon is capturing in background on NUC)
    # ======================================================================
    logger().info("Starting test execution (btmon running on NUC)...")
    time.sleep(5)

    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture()
        time.sleep(5)
        ble_test = BLESMPPairingTest(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            dut_capability="DisplayOnly",
            client_capability="DisplayOnly",
            pin_code="-8",
            test_case_id=test_case_id,
        )
        ble_test.run()
        time.sleep(5)

        dut_address = ble_test.dut_address
        nuc_address = ble_test.nuc_address
        logger().info(f"DUT address: {dut_address}")
        logger().info(f"NUC address: {nuc_address}")
        dut_address_hex = re.split(":", dut_address)
        nuc_address_hex = re.split(":", nuc_address)
        master_address = "0x"
        for hex_data_part in dut_address_hex:   
            master_address = master_address + hex_data_part
        slave_address = "0x"
        for hex_data_part in nuc_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
    finally:
        # ======================================================================
        # Stop btmon on NUC and retrieve the log
        # ======================================================================
        logger().info("=" * 80)
        logger().info("Stopping btmon on NUC and retrieving log...")
        logger().info("=" * 80)

        try:
            # Stop btmon
            if btmon_command:
                btmon_command.stop()
            nuc_shell.execute("sudo pkill btmon")
            time.sleep(2)

            # Check if log file exists
            rc, stdout, stderr = nuc_shell.execute(f"ls -lh {remote_btmon_log}")
            logger().info(f"Remote btmon log file info: {stdout}")

            # Download btmon log from NUC to local machine
            logger().info(f"Downloading btmon log from NUC to {bt_mon_log_file}")
            with nuc_shell.client.open_sftp() as sftp:
                sftp.get(remote_btmon_log, bt_mon_log_file)

            logger().info(f"✓ btmon log downloaded: {bt_mon_log_file}")

            # Clean up remote file
            nuc_shell.execute(f"rm -f {remote_btmon_log}")

        except Exception as e:
            logger().error(f"Failed to retrieve btmon log from NUC: {e}")

    logger().info("=" * 80)
    logger().info(f"✅ Test completed. NUC btmon log saved to: {bt_mon_log_file}")
    logger().info("=" * 80)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize("test_case_id",["C554026",
                        "C554027","C554028","C554029",
                        "C554030"])
@pytest.mark.test_src_map_id('C554026','C554027','C554028','C554029','C554030')
def test_verify_nuc_as_ble_client_ag_C554026_to_C554030(wifi_dut, ble_client,test_case_id,ble_sniffer):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    # Generate unique btmon log filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file = f"reports/ag_test_btmon_NUC_{timestamp}_{test_case_id}.log"
    remote_btmon_log = f"/tmp/btmon_ag_{timestamp}_{test_case_id}.log"

    # Access NUC shell
    nuc_shell = ble_client.interfaces.nuc_host_shell
    btmon_command = None

    # ======================================================================
    # Start btmon on NUC BEFORE the test
    # ======================================================================
    logger().info("=" * 80)
    logger().info(f"Starting btmon on NUC (10.207.20.149)")
    logger().info(f"Remote log: {remote_btmon_log}")
    logger().info("=" * 80)

    try:
        # Kill any existing btmon processes
        nuc_shell.execute("sudo pkill btmon")
        time.sleep(1)

        # Start btmon in background on NUC
        btmon_command = nuc_shell.execute_in_background(
            f"sudo btmon -t > {remote_btmon_log} 2>&1"
        )
        time.sleep(2)  # Give btmon time to start
        logger().info("✓ btmon started on NUC")

    except Exception as e:
        logger().error(f"Failed to start btmon on NUC: {e}")

    # ======================================================================
    # Execute pre-test commands on NUC/BLE client
    # ======================================================================
    logger().info("=" * 80)
    logger().info("Executing pre-test commands on NUC/BLE client...")
    logger().info("=" * 80)
    

    try:

        # Check Bluetooth status
        rc, stdout, stderr = nuc_shell.execute("hciconfig -a")
        logger().info(f"HCI Config output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pulseaudio -k")
        logger().info(f"Pulseaudio output:\n{stdout}")

        time.sleep(2)

        rc, stdout, stderr = nuc_shell.execute("pulseaudio --start")
        logger().info(f"Pulseaudio output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluez5-discover")
        logger().info(f"pactl bluez5 modules:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluetooth-discover")
        logger().info(f"pactl bluetooth modules:\n{stdout}")

    except Exception as e:
        logger().error(f"Failed to execute pre-test commands on NUC: {e}")
        # Decide if you want to fail the test or continue
        # raise  # Uncomment to fail test on command execution error

    logger().info("Pre-test commands completed")
    logger().info("=" * 80)

    # ======================================================================
    # Run the actual test (btmon is capturing in background on NUC)
    # ======================================================================
    logger().info("Starting test execution (btmon running on NUC)...")
    time.sleep(5)

    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture()
        time.sleep(5)
        ble_test = BLESMPPairingTest(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            dut_capability="DisplayOnly",
            client_capability="DisplayOnly",
            pin_code="-8",
            test_case_id=test_case_id,
        )
        ble_test.run()
        time.sleep(5)

        dut_address = ble_test.dut_address
        nuc_address = ble_test.nuc_address
        logger().info(f"DUT address: {dut_address}")
        logger().info(f"NUC address: {nuc_address}")
        dut_address_hex = re.split(":", dut_address)
        nuc_address_hex = re.split(":", nuc_address)
        master_address = "0x"
        for hex_data_part in dut_address_hex:   
            master_address = master_address + hex_data_part
        slave_address = "0x"
        for hex_data_part in nuc_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
    finally:
        # ======================================================================
        # Stop btmon on NUC and retrieve the log
        # ======================================================================
        logger().info("=" * 80)
        logger().info("Stopping btmon on NUC and retrieving log...")
        logger().info("=" * 80)

        try:
            # Stop btmon
            if btmon_command:
                btmon_command.stop()
            nuc_shell.execute("sudo pkill btmon")
            time.sleep(2)

            # Check if log file exists
            rc, stdout, stderr = nuc_shell.execute(f"ls -lh {remote_btmon_log}")
            logger().info(f"Remote btmon log file info: {stdout}")

            # Download btmon log from NUC to local machine
            logger().info(f"Downloading btmon log from NUC to {bt_mon_log_file}")
            with nuc_shell.client.open_sftp() as sftp:
                sftp.get(remote_btmon_log, bt_mon_log_file)

            logger().info(f"✓ btmon log downloaded: {bt_mon_log_file}")

            # Clean up remote file
            nuc_shell.execute(f"rm -f {remote_btmon_log}")

        except Exception as e:
            logger().error(f"Failed to retrieve btmon log from NUC: {e}")

    logger().info("=" * 80)
    logger().info(f"✅ Test completed. NUC btmon log saved to: {bt_mon_log_file}")
    logger().info("=" * 80)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize("test_case_id",
                        ["C554031","C554032","C554033",
                        "C554034","C554035"])
@pytest.mark.test_src_map_id('C554031','C554032','C554033','C554034','C554035')
def test_verify_nuc_as_ble_client_ag_C554031_to_C554035(wifi_dut, ble_client,test_case_id,ble_sniffer):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    # Generate unique btmon log filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file = f"reports/ag_test_btmon_NUC_{timestamp}_{test_case_id}.log"
    remote_btmon_log = f"/tmp/btmon_ag_{timestamp}_{test_case_id}.log"

    # Access NUC shell
    nuc_shell = ble_client.interfaces.nuc_host_shell
    btmon_command = None

    # ======================================================================
    # Start btmon on NUC BEFORE the test
    # ======================================================================
    logger().info("=" * 80)
    logger().info(f"Starting btmon on NUC (10.207.20.149)")
    logger().info(f"Remote log: {remote_btmon_log}")
    logger().info("=" * 80)

    try:
        # Kill any existing btmon processes
        nuc_shell.execute("sudo pkill btmon")
        time.sleep(1)

        # Start btmon in background on NUC
        btmon_command = nuc_shell.execute_in_background(
            f"sudo btmon -t > {remote_btmon_log} 2>&1"
        )
        time.sleep(2)  # Give btmon time to start
        logger().info("✓ btmon started on NUC")

    except Exception as e:
        logger().error(f"Failed to start btmon on NUC: {e}")

    # ======================================================================
    # Execute pre-test commands on NUC/BLE client
    # ======================================================================
    logger().info("=" * 80)
    logger().info("Executing pre-test commands on NUC/BLE client...")
    logger().info("=" * 80)
    
    try:

        # Check Bluetooth status
        rc, stdout, stderr = nuc_shell.execute("hciconfig -a")
        logger().info(f"HCI Config output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pulseaudio -k")
        logger().info(f"Pulseaudio output:\n{stdout}")

        time.sleep(2)

        rc, stdout, stderr = nuc_shell.execute("pulseaudio --start")
        logger().info(f"Pulseaudio output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluez5-discover")
        logger().info(f"pactl bluez5 modules:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluetooth-discover")
        logger().info(f"pactl bluetooth modules:\n{stdout}")

    except Exception as e:
        logger().error(f"Failed to execute pre-test commands on NUC: {e}")
        # Decide if you want to fail the test or continue
        # raise  # Uncomment to fail test on command execution error

    logger().info("Pre-test commands completed")
    logger().info("=" * 80)

    # ======================================================================
    # Run the actual test (btmon is capturing in background on NUC)
    # ======================================================================
    logger().info("Starting test execution (btmon running on NUC)...")
    time.sleep(5)

    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture()
        time.sleep(5)
        ble_test = BLESMPPairingTest(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            dut_capability="DisplayOnly",
            client_capability="DisplayOnly",
            pin_code="-8",
            test_case_id=test_case_id,
        )
        ble_test.run()
        time.sleep(5)

        dut_address = ble_test.dut_address
        nuc_address = ble_test.nuc_address
        logger().info(f"DUT address: {dut_address}")
        logger().info(f"NUC address: {nuc_address}")
        dut_address_hex = re.split(":", dut_address)
        nuc_address_hex = re.split(":", nuc_address)
        master_address = "0x"
        for hex_data_part in dut_address_hex:   
            master_address = master_address + hex_data_part
        slave_address = "0x"
        for hex_data_part in nuc_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
    finally:
        # ======================================================================
        # Stop btmon on NUC and retrieve the log
        # ======================================================================
        logger().info("=" * 80)
        logger().info("Stopping btmon on NUC and retrieving log...")
        logger().info("=" * 80)

        try:
            # Stop btmon
            if btmon_command:
                btmon_command.stop()
            nuc_shell.execute("sudo pkill btmon")
            time.sleep(2)

            # Check if log file exists
            rc, stdout, stderr = nuc_shell.execute(f"ls -lh {remote_btmon_log}")
            logger().info(f"Remote btmon log file info: {stdout}")

            # Download btmon log from NUC to local machine
            logger().info(f"Downloading btmon log from NUC to {bt_mon_log_file}")
            with nuc_shell.client.open_sftp() as sftp:
                sftp.get(remote_btmon_log, bt_mon_log_file)

            logger().info(f"✓ btmon log downloaded: {bt_mon_log_file}")

            # Clean up remote file
            nuc_shell.execute(f"rm -f {remote_btmon_log}")

        except Exception as e:
            logger().error(f"Failed to retrieve btmon log from NUC: {e}")

    logger().info("=" * 80)
    logger().info(f"✅ Test completed. NUC btmon log saved to: {bt_mon_log_file}")
    logger().info("=" * 80)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize("test_case_id",["C554039"])
                        # ["C554036","C554037","C554038",
                        # "C554039","C554042","C554043"])
@pytest.mark.test_src_map_id('C554039')#,'C554037','C554038','C554039','C554042','C554043')
def test_verify_nuc_as_ble_client_ag_C554036_to_C554044(wifi_dut, ble_client,test_case_id,ble_sniffer):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    # Generate unique btmon log filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file = f"reports/ag_test_btmon_NUC_{timestamp}_{test_case_id}.log"
    remote_btmon_log = f"/tmp/btmon_ag_{timestamp}_{test_case_id}.log"

    # Access NUC shell
    nuc_shell = ble_client.interfaces.nuc_host_shell
    btmon_command = None

    # ======================================================================
    # Start btmon on NUC BEFORE the test
    # ======================================================================
    logger().info("=" * 80)
    logger().info(f"Starting btmon on NUC (10.208.71.220)")
    logger().info(f"Remote log: {remote_btmon_log}")
    logger().info("=" * 80)

    try:
        # Kill any existing btmon processes
        nuc_shell.execute("sudo pkill btmon")
        time.sleep(1)

        # Start btmon in background on NUC
        btmon_command = nuc_shell.execute_in_background(
            f"sudo btmon -t > {remote_btmon_log} 2>&1"
        )
        time.sleep(2)  # Give btmon time to start
        logger().info("✓ btmon started on NUC")

    except Exception as e:
        logger().error(f"Failed to start btmon on NUC: {e}")

    # ======================================================================
    # Execute pre-test commands on NUC/BLE client
    # ======================================================================
    logger().info("=" * 80)
    logger().info("Executing pre-test commands on NUC/BLE client...")
    logger().info("=" * 80)

    try:

        # Check Bluetooth status
        rc, stdout, stderr = nuc_shell.execute("hciconfig -a")
        logger().info(f"HCI Config output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pulseaudio -k")
        logger().info(f"Pulseaudio output:\n{stdout}")

        time.sleep(2)

        rc, stdout, stderr = nuc_shell.execute("pulseaudio --start")
        logger().info(f"Pulseaudio output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluez5-discover")
        logger().info(f"pactl bluez5 modules:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluetooth-discover")
        logger().info(f"pactl bluetooth modules:\n{stdout}")

    except Exception as e:
        logger().error(f"Failed to execute pre-test commands on NUC: {e}")
        # Decide if you want to fail the test or continue
        # raise  # Uncomment to fail test on command execution error

    logger().info("Pre-test commands completed")
    logger().info("=" * 80)

    # ======================================================================
    # Run the actual test (btmon is capturing in background on NUC)
    # ======================================================================
    logger().info("Starting test execution (btmon running on NUC)...")
    time.sleep(5)
    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture()
        time.sleep(5)
        ble_test = BLESMPPairingTest(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            dut_capability="DisplayOnly",
            client_capability="DisplayOnly",
            pin_code="-8",
            test_case_id=test_case_id,
        )
        ble_test.run()
        time.sleep(5)

        dut_address = ble_test.dut_address
        nuc_address = ble_test.nuc_address
        logger().info(f"DUT address: {dut_address}")
        logger().info(f"NUC address: {nuc_address}")
        dut_address_hex = re.split(":", dut_address)
        nuc_address_hex = re.split(":", nuc_address)
        master_address = "0x"
        for hex_data_part in dut_address_hex:   
            master_address = master_address + hex_data_part
        slave_address = "0x"
        for hex_data_part in nuc_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
    finally:
        # ======================================================================
        # Stop btmon on NUC and retrieve the log
        # ======================================================================
        logger().info("=" * 80)
        logger().info("Stopping btmon on NUC and retrieving log...")
        logger().info("=" * 80)

        try:
            # Stop btmon
            if btmon_command:
                btmon_command.stop()
            nuc_shell.execute("sudo pkill btmon")
            time.sleep(2)

            # Check if log file exists
            rc, stdout, stderr = nuc_shell.execute(f"ls -lh {remote_btmon_log}")
            logger().info(f"Remote btmon log file info: {stdout}")

            # Download btmon log from NUC to local machine
            logger().info(f"Downloading btmon log from NUC to {bt_mon_log_file}")
            with nuc_shell.client.open_sftp() as sftp:
                sftp.get(remote_btmon_log, bt_mon_log_file)

            logger().info(f"✓ btmon log downloaded: {bt_mon_log_file}")

            # Clean up remote file
            nuc_shell.execute(f"rm -f {remote_btmon_log}")

        except Exception as e:
            logger().error(f"Failed to retrieve btmon log from NUC: {e}")

    logger().info("=" * 80)
    logger().info(f"✅ Test completed. NUC btmon log saved to: {bt_mon_log_file}")
    logger().info("=" * 80)