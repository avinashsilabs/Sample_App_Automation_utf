import os
import time
import datetime
import subprocess
import pytest
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from dataclasses import dataclass, field
import re

"""
####################################################################
                    Raspi A2DP Sniff Mode Test

                    Setup Requirements:
                    1. Raspberry Pi 4 (as A2DP Sink)
                    2. DUT (RS9116/916)
                    3. btmon for HCI logging, btsnoop binary capture

                    Description:
                    Raspi advertises as A2DP Sink and enables Sniff Mode. The DUT connects and streams
                    audio to the Raspi. Sniff Mode is enabled for a period of time and then disabled.Audio
                    Stream after Sniff Mode is disabled.
                    Captures:
                      - btmon text log  (HCI traffic)
                      - btsnoop binary  (raw HCI capture, Wireshark-readable)   

                    Author: Sailish Behal
####################################################################
"""

def logger():
    return get_logger(__name__)


# --- Module-level cached DUT BD address ---
_cached_dut_address = None
_BD_ADDR_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def get_dut_address(wifi_dut):
    """
    Retrieve the DUT BD address dynamically via CLI and cache it for all
    subsequent test cases.  No hardcoded fallback — the address is always
    queried from the DUT so the script works on any setup without edits.

    Returns:
        str: BD address in XX:XX:XX:XX:XX:XX format.

    Raises:
        RuntimeError: If the address cannot be retrieved.
    """
    global _cached_dut_address
    if _cached_dut_address is not None:
        logger().info(f"DUT BD Address (cached): {_cached_dut_address}")
        return _cached_dut_address

    try:
        dynamic_address = wifi_dut.interfaces.wifi.get_local_address()
        if dynamic_address and _BD_ADDR_PATTERN.match(dynamic_address.strip()):
            _cached_dut_address = dynamic_address.strip()
            logger().info(f"DUT BD Address (retrieved dynamically): {_cached_dut_address}")
            return _cached_dut_address
        else:
            raise RuntimeError(
                f"get_local_address() returned invalid/empty value: '{dynamic_address}'. "
                f"Ensure the DUT is powered on and the 'btc gap get_local_address' CLI command is available."
            )
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(
            f"Failed to retrieve DUT BD address: {e}. "
            f"Ensure the DUT is powered on and the 'btc gap get_local_address' CLI command is available."
        )


def inter_test_wait(request, seconds=60):
    """
    Wait between consecutive test cases, but only when the full test plan is
    being executed (more than one test selected). When a test case is run in
    isolation, the wait is skipped.

    Args:
        request: pytest ``request`` fixture (provides ``request.session.items``).
        seconds: ``int`` number of seconds to wait between test cases.
    """
    if len(request.session.items) > 1:
        logger().info(
            f"Full test plan detected - waiting {seconds} seconds before the next test case starts..."
        )
        time.sleep(seconds)
    else:
        logger().info("Single test case run detected - skipping the inter-test wait.")


# =============================================================================
# btsnoop Binary Capture
# =============================================================================

class BtsnoopCaptureManager:
    """
    Manages btsnoop binary capture using btmon -w command.

    btsnoop files can be analyzed later with:
    - Wireshark (GUI)
    - tshark (CLI)
    - Direct binary parsing

    The btsnoop format captures raw HCI packets which include
    the full Bluetooth protocol stack including RTP for A2DP.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.btmon_process = None
        self.btsnoop_file = None
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        """Ensure output directory exists"""
        os.makedirs(self.output_dir, exist_ok=True)

    def start_capture(self, filename: str = None) -> str:
        """
        Start btmon capture to btsnoop binary file.

        Args:
            filename: Output filename (auto-generated if None)

        Returns:
            Path to btsnoop file
        """
        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"a2dp_stream_{timestamp}.btsnoop"

        self.btsnoop_file = os.path.join(self.output_dir, filename)

        logger().info(f"Starting btsnoop capture: {self.btsnoop_file}")

        # Start btmon with write to file option: sudo btmon -w <filename>
        cmd = ["sudo", "btmon", "-w", self.btsnoop_file]

        try:
            self.btmon_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True  # Allows process to continue independently
            )
            logger().info(f"btmon capture started (PID: {self.btmon_process.pid})")
            time.sleep(1)  # Give btmon time to initialize
            return self.btsnoop_file
        except Exception as e:
            logger().error(f"Failed to start btmon capture: {e}")
            return None

    def stop_capture(self) -> str:
        """
        Stop btmon capture.

        Returns:
            Path to captured btsnoop file
        """
        if self.btmon_process:
            logger().info("Stopping btmon capture...")
            try:
                # Send SIGTERM to btmon process
                subprocess.run(["sudo", "kill", str(self.btmon_process.pid)],
                               capture_output=True, timeout=5)
                self.btmon_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if needed
                subprocess.run(["sudo", "kill", "-9", str(self.btmon_process.pid)],
                               capture_output=True)
            except Exception as e:
                logger().warning(f"Error stopping btmon: {e}")

            self.btmon_process = None

        # Verify file exists and has content
        if self.btsnoop_file and os.path.exists(self.btsnoop_file):
            size = os.path.getsize(self.btsnoop_file)
            logger().info(f"btsnoop capture stopped. File size: {size} bytes")
            return self.btsnoop_file
        else:
            logger().warning("btsnoop file not found or empty")
            return None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure capture is stopped"""
        self.stop_capture()


# =============================================================================
# AVRCP Pause + Sniff Mode enable ONLY, no resume (sniff timeout = 2) and (sniff interval=500ms)
# =============================================================================

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553484(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - AVRCP Pause / Sniff Mode enable (no resume) test.

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 500 ms, attempt = 2, timeout = 2) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for the remainder of the 120 s pause window.
      5. After the Sniff Mode interval, verify the DUT is still connected
         (test PASSES if the link is up, FAILS if it dropped). Audio streaming
         is NOT resumed (no AVRCP Play is issued).

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x0320 (800 slots = 500 ms)
      min_interval = 0x0320 (800 slots = 500 ms)
      attempt      = 0x0002
      timeout      = 0x0002

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_ble_a2dp.py::test_raspi_a2dp_sink_C553484
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 120   # seconds - idle time after AVRCP Pause
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - AVRCP PAUSE / RESUME TEST")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")
    time.sleep(10)
    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → wait remaining 80 s
            #           (total pause window = 120 s)
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 80 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            sniff_params = "0x20 0x03 0x20 0x03 0x02 0x00 0x02 0x00"
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params=sniff_params
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE
            logger().info(f"Phase 2: Waiting remaining {sniff_idle} seconds in Sniff Mode...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Connection-state check after the Sniff Mode interval:
            #   - if the ACL link is still up  -> test PASSES
            #   - if the link has dropped      -> test FAILS
            # ------------------------------------------------------------------
            logger().info("Checking connection state after Sniff Mode interval...")
            conn_state = raspi_bt.get_bt_connection_status(dut_bt_address)
            logger().info(f"Connection state after Sniff Mode interval: {conn_state}")
            assert conn_state, (
                f"Connection to DUT {dut_bt_address} was LOST after the Sniff Mode interval; "
                "expected the link to remain connected."
            )
            logger().info("ASSERT PASSED: Connection is still active after Sniff Mode interval")

            # Streaming is NOT resumed after the Sniff Mode interval; the test
            # ends with the DUT left in Sniff Mode.
            logger().info("Test complete: DUT left in Sniff Mode, audio NOT resumed.")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        time.sleep(10)
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)

# =============================================================================
# AVRCP Pause + Sniff Mode enable ONLY, no resume (sniff timeout = 5) and (sniff interval=500ms)
# =============================================================================
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553485(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - AVRCP Pause / Sniff Mode enable (no resume) test.

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 500 ms, attempt = 2, timeout = 5) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for the remainder of the 120 s pause window.
      5. After the Sniff Mode interval, verify the DUT is still connected
         (test PASSES if the link is up, FAILS if it dropped). Audio streaming
         is NOT resumed (no AVRCP Play is issued).

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x0320 (800 slots = 500 ms)
      min_interval = 0x0320 (800 slots = 500 ms)
      attempt      = 0x0002
      timeout      = 0x0005

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_ble_a2dp.py::test_raspi_a2dp_sink_C553485
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 120   # seconds - idle time after AVRCP Pause
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - AVRCP PAUSE / RESUME TEST")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")
    time.sleep(10)
    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → wait remaining 80 s
            #           (total pause window = 120 s)
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 80 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            sniff_params = "0x20 0x03 0x20 0x03 0x02 0x00 0x05 0x00"
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params=sniff_params
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE
            logger().info(f"Phase 2: Waiting remaining {sniff_idle} seconds in Sniff Mode...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Connection-state check after the Sniff Mode interval:
            #   - if the ACL link is still up  -> test PASSES
            #   - if the link has dropped      -> test FAILS
            # ------------------------------------------------------------------
            logger().info("Checking connection state after Sniff Mode interval...")
            conn_state = raspi_bt.get_bt_connection_status(dut_bt_address)
            logger().info(f"Connection state after Sniff Mode interval: {conn_state}")
            assert conn_state, (
                f"Connection to DUT {dut_bt_address} was LOST after the Sniff Mode interval; "
                "expected the link to remain connected."
            )
            logger().info("ASSERT PASSED: Connection is still active after Sniff Mode interval")

            # Streaming is NOT resumed after the Sniff Mode interval; the test
            # ends with the DUT left in Sniff Mode.
            logger().info("Test complete: DUT left in Sniff Mode, audio NOT resumed.")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        time.sleep(10)
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)


# =============================================================================
# AVRCP Pause + Sniff Mode enable ONLY, no resume (sniff interval=100ms, attempt=3, timeout=5)
# =============================================================================
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553486(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - AVRCP Pause / Sniff Mode enable (no resume) test.

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 100 ms, attempt = 3, timeout = 5) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for the remainder of the 120 s pause window.
      5. After the Sniff Mode interval, verify the DUT is still connected
         (test PASSES if the link is up, FAILS if it dropped). Audio streaming
         is NOT resumed (no AVRCP Play is issued).

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x00A0 (160 slots = 100 ms)
      min_interval = 0x00A0 (160 slots = 100 ms)
      attempt      = 0x0003
      timeout      = 0x0005

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_ble_a2dp.py::test_raspi_a2dp_sink_C553486
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 120   # seconds - idle time after AVRCP Pause
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - AVRCP PAUSE / RESUME TEST")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")
    time.sleep(10)
    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → wait remaining 80 s
            #           (total pause window = 120 s)
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 80 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            sniff_params = "0xa0 0x00 0xa0 0x00 0x03 0x00 0x05 0x00"
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params=sniff_params
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE
            logger().info(f"Phase 2: Waiting remaining {sniff_idle} seconds in Sniff Mode...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Connection-state check after the Sniff Mode interval:
            #   - if the ACL link is still up  -> test PASSES
            #   - if the link has dropped      -> test FAILS
            # ------------------------------------------------------------------
            logger().info("Checking connection state after Sniff Mode interval...")
            conn_state = raspi_bt.get_bt_connection_status(dut_bt_address)
            logger().info(f"Connection state after Sniff Mode interval: {conn_state}")
            assert conn_state, (
                f"Connection to DUT {dut_bt_address} was LOST after the Sniff Mode interval; "
                "expected the link to remain connected."
            )
            logger().info("ASSERT PASSED: Connection is still active after Sniff Mode interval")

            # Streaming is NOT resumed after the Sniff Mode interval; the test
            # ends with the DUT left in Sniff Mode.
            logger().info("Test complete: DUT left in Sniff Mode, audio NOT resumed.")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        time.sleep(10)
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)


# =============================================================================
# AVRCP Pause + Sniff Mode enable ONLY, no resume (sniff interval=100ms, attempt=3, timeout=2)
# =============================================================================
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553487(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - AVRCP Pause / Sniff Mode enable (no resume) test.

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 100 ms, attempt = 3, timeout = 2) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for the remainder of the 120 s pause window.
      5. After the Sniff Mode interval, verify the DUT is still connected
         (test PASSES if the link is up, FAILS if it dropped). Audio streaming
         is NOT resumed (no AVRCP Play is issued).

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x00A0 (160 slots = 100 ms)
      min_interval = 0x00A0 (160 slots = 100 ms)
      attempt      = 0x0003
      timeout      = 0x0002

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_ble_a2dp.py::test_raspi_a2dp_sink_C553487
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 120   # seconds - idle time after AVRCP Pause
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - AVRCP PAUSE / RESUME TEST")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")
    time.sleep(10)
    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → wait remaining 80 s
            #           (total pause window = 120 s)
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 80 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            sniff_params = "0xa0 0x00 0xa0 0x00 0x03 0x00 0x02 0x00"
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params=sniff_params
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE
            logger().info(f"Phase 2: Waiting remaining {sniff_idle} seconds in Sniff Mode...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Connection-state check after the Sniff Mode interval:
            #   - if the ACL link is still up  -> test PASSES
            #   - if the link has dropped      -> test FAILS
            # ------------------------------------------------------------------
            logger().info("Checking connection state after Sniff Mode interval...")
            conn_state = raspi_bt.get_bt_connection_status(dut_bt_address)
            logger().info(f"Connection state after Sniff Mode interval: {conn_state}")
            assert conn_state, (
                f"Connection to DUT {dut_bt_address} was LOST after the Sniff Mode interval; "
                "expected the link to remain connected."
            )
            logger().info("ASSERT PASSED: Connection is still active after Sniff Mode interval")

            # Streaming is NOT resumed after the Sniff Mode interval; the test
            # ends with the DUT left in Sniff Mode.
            logger().info("Test complete: DUT left in Sniff Mode, audio NOT resumed.")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        time.sleep(10)
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)


# =============================================================================
# AVRCP Pause + Sniff Mode enable ONLY (no AVRCP Play / no resume streaming)
# (sniff interval=100ms, attempt=3, timeout=2)
# =============================================================================
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553488(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - AVRCP Pause / Sniff Mode enable ONLY test.

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 100 ms, attempt = 3, timeout = 2) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for the remainder of the 120 s pause window.
         The test ENDS in Sniff Mode - audio streaming is NOT resumed
         (no AVRCP Play is issued).

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x00A0 (160 slots = 100 ms)
      min_interval = 0x00A0 (160 slots = 100 ms)
      attempt      = 0x0003
      timeout      = 0x0002

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_btc_sniff.py::test_raspi_a2dp_sink_C553488
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 120   # seconds - idle time after AVRCP Pause
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - AVRCP PAUSE / SNIFF MODE ENABLE ONLY")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")

    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → hold in Sniff Mode
            #           (total pause window = 120 s). NO AVRCP Play / NO resume.
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 80 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params="0xa0 0x00 0xa0 0x00 0x03 0x00 0x02 0x00"
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            # Hold in Sniff Mode for the remainder of the pause window.
            # Audio streaming is NOT resumed (no AVRCP Play is issued).
            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE
            logger().info(f"Phase 2: Holding in Sniff Mode for {sniff_idle} seconds (no resume)...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Connection-state check after the Sniff Mode interval:
            #   - if the ACL link is still up  -> test PASSES
            #   - if the link has dropped      -> test FAILS
            # ------------------------------------------------------------------
            logger().info("Checking connection state after Sniff Mode interval...")
            conn_state = raspi_bt.get_bt_connection_status(dut_bt_address)
            logger().info(f"Connection state after Sniff Mode interval: {conn_state}")
            assert conn_state, (
                f"Connection to DUT {dut_bt_address} was LOST after the Sniff Mode interval; "
                "expected the link to remain connected."
            )
            logger().info("ASSERT PASSED: Connection is still active after Sniff Mode interval")

            logger().info("Test complete: DUT left in Sniff Mode, audio NOT resumed.")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)


# =============================================================================
# AVRCP Pause + Sniff Mode enable ONLY - 10 MINUTE Sniff Mode hold
# (sniff interval=100ms, attempt=3, timeout=2)
# =============================================================================
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553490(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - AVRCP Pause / Sniff Mode enable ONLY test (10 min hold).

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 100 ms, attempt = 3, timeout = 2) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for 10 minutes (600 seconds). The test ENDS in
         Sniff Mode - audio streaming is NOT resumed (no AVRCP Play is issued).
      5. After the Sniff Mode interval, verify the connection is still active:
         if the ACL link is up the test PASSES, otherwise it FAILS.

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x00A0 (160 slots = 100 ms)
      min_interval = 0x00A0 (160 slots = 100 ms)
      attempt      = 0x0003
      timeout      = 0x0002

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_btc_sniff.py::test_raspi_a2dp_sink_C553490
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 645   # seconds - idle window sized so the DUT stays
                                   #           in Sniff Mode for ~10 minutes
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - AVRCP PAUSE / SNIFF MODE ENABLE ONLY (10 MIN HOLD)")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")

    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → hold in Sniff Mode
            #           for 10 minutes. NO AVRCP Play / NO resume.
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 605 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params="0xa0 0x00 0xa0 0x00 0x03 0x00 0x02 0x00"
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            # Hold in Sniff Mode for 10 minutes (600 seconds).
            # Audio streaming is NOT resumed (no AVRCP Play is issued).
            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE  # 600 s (10 minutes)
            logger().info(f"Phase 2: Holding in Sniff Mode for {sniff_idle} seconds (~10 min, no resume)...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Connection-state check after the Sniff Mode interval:
            #   - if the ACL link is still up  -> test PASSES
            #   - if the link has dropped      -> test FAILS
            # ------------------------------------------------------------------
            logger().info("Checking connection state after Sniff Mode interval...")
            conn_state = raspi_bt.get_bt_connection_status(dut_bt_address)
            logger().info(f"Connection state after Sniff Mode interval: {conn_state}")
            assert conn_state, (
                f"Connection to DUT {dut_bt_address} was LOST after the Sniff Mode interval; "
                "expected the link to remain connected."
            )
            logger().info("ASSERT PASSED: Connection is still active after Sniff Mode interval")

            logger().info("Test complete: DUT left in Sniff Mode, audio NOT resumed.")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)


# =============================================================================
# Focus: streaming AFTER Sniff Mode is DISABLED
# AVRCP Pause / Sniff Mode / Resume streaming for 2 min after sniff disabled
# (sniff interval=500ms, attempt=2, timeout=2)
# =============================================================================
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553489(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - streaming AFTER Sniff Mode disabled test.

    This test focuses on verifying that A2DP audio streaming resumes correctly
    once Sniff Mode has been disabled (via AVRCP Play).

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 500 ms, attempt = 2, timeout = 2) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for the remainder of the 120 s pause window.
      5. Issue AVRCP Play (bt_avrcp_play) from the DUT and assert the
         'AVRCP Play triggered' and 'SNIFF_MODE_DISABLED' events on the DUT
         serial log. FOCUS: after Sniff Mode is DISABLED, resume audio
         streaming and verify it streams for 2 minutes (120 seconds).

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x0320 (800 slots = 500 ms)
      min_interval = 0x0320 (800 slots = 500 ms)
      attempt      = 0x0002
      timeout      = 0x0002

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_btc_sniff.py::test_raspi_a2dp_sink_C553489
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 120   # seconds - idle time after AVRCP Pause
    STREAM_PHASE3_DURATION = 120   # seconds - streaming after sniff mode disabled (2 min)
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - STREAMING AFTER SNIFF MODE DISABLED TEST")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")

    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → wait remaining 80 s
            #           (total pause window = 120 s)
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 80 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params="0x20 0x03 0x20 0x03 0x02 0x00 0x02 0x00"
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE
            logger().info(f"Phase 2: Waiting remaining {sniff_idle} seconds in Sniff Mode...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 3: AVRCP Play → assert play + sniff disabled events
            #           → FOCUS: stream for 2 minutes (120 s) after sniff disabled
            # ------------------------------------------------------------------
            logger().info("Phase 3: Initiating AVRCP Play...")
            play_result = wifi_dut.interfaces.wifi.bt_avrcp_play(raspi_address)
            logger().info(f"AVRCP Play command sent. Result: {play_result}")

            # Wait briefly for AVRCP Play triggered and SNIFF_MODE_DISABLED events to arrive
            PLAY_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 3: Waiting {PLAY_EVENT_SETTLE} seconds for play/sniff-disabled events...")
            time.sleep(PLAY_EVENT_SETTLE)

            # Read fresh serial log slice and assert both events
            play_event_log = serial_conn.get_input_log()
            play_event_lines = [
                line.decode(errors="ignore")
                for ts, line in play_event_log
            ]
            for pl in play_event_lines:
                logger().info(f"PLAY_EVENT_LOG: {pl}")

            assert any(
                f"AVRCP Play triggered: {raspi_address}" in pl for pl in play_event_lines
            ), (
                f"AVRCP Play triggered event for {raspi_address} not received on DUT serial log "
                "after bt_avrcp_play command"
            )
            logger().info("ASSERT PASSED: AVRCP Play triggered event confirmed in serial log")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_DISABLED" in pl
                for pl in play_event_lines
            ), (
                f"SNIFF_MODE_DISABLED event for {raspi_address} not received on DUT serial log "
                "after AVRCP Play command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_DISABLED event confirmed in serial log")

            # 'A2DP Source start event' and 'A2DP audio' also appear from the
            # Phase-1 start and get_input_log() is cumulative, so require a 2nd
            # occurrence to prove streaming actually resumed after Sniff disable.
            start_evt_count = sum(
                pl.count(f"A2DP Source start event: {raspi_address}") for pl in play_event_lines
            )
            a2dp_audio_count = sum(pl.count("A2DP audio") for pl in play_event_lines)
            assert start_evt_count >= 2, (
                "A2DP Source start event did not repeat after AVRCP Play "
                f"(expected >=2, found {start_evt_count}); streaming may not have resumed"
            )
            assert a2dp_audio_count >= 2, (
                "A2DP audio marker did not repeat after AVRCP Play "
                f"(expected >=2, found {a2dp_audio_count}); streaming may not have resumed"
            )
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio resumed after Sniff Mode disabled")

            # FOCUS: stream audio for 2 minutes (120 s) after Sniff Mode is disabled
            stream3_remaining = STREAM_PHASE3_DURATION - PLAY_EVENT_SETTLE
            logger().info(f"Phase 3: Streaming for {stream3_remaining} seconds after Sniff Mode disabled...")
            elapsed = 0
            while elapsed < stream3_remaining:
                remaining = stream3_remaining - elapsed
                logger().info(f"[Phase 3 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # Check audio file size
            try:
                captured_audio_size = raspi_bt.bt_service.read_file_size(capture_file_path)
                logger().info(f"Captured audio size: {captured_audio_size} bytes")
            except Exception as e:
                logger().warning(f"Could not read audio file: {e}")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)


# =============================================================================
# Focus: streaming AFTER Sniff Mode is DISABLED
# AVRCP Pause / Sniff Mode / Resume streaming for 10 min after sniff disabled
# (sniff interval=500ms, attempt=2, timeout=2)
# =============================================================================
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_raspi_a2dp_sink_C553494(bt_client, wifi_dut, request, ble_sniffer):
    """
    Raspi A2DP Sink - streaming AFTER Sniff Mode disabled test (10 min stream).

    This test focuses on verifying that A2DP audio streaming resumes correctly
    once Sniff Mode has been disabled (via AVRCP Play).

    Test flow:
      1. Connect DUT to Raspi (A2DP Sink) and stream A2DP audio for 120 seconds.
      2. Issue AVRCP Pause (bt_avrcp_pause) from the DUT and assert the
         'avrcp pause event' and 'A2DP Source suspend event' on the DUT serial log.
      3. 40 seconds after the pause, enable Sniff Mode from the Raspi side
         (max/min interval = 500 ms, attempt = 2, timeout = 2) and assert the
         'SNIFF_MODE_ENABLED' mode-change event on the DUT serial log.
      4. Hold in Sniff Mode for the remainder of the 120 s pause window.
      5. Issue AVRCP Play (bt_avrcp_play) from the DUT and assert the
         'AVRCP Play triggered' and 'SNIFF_MODE_DISABLED' events on the DUT
         serial log. FOCUS: after Sniff Mode is DISABLED, resume audio
         streaming and verify it streams for 10 minutes (600 seconds).

    HCI Sniff Mode params (all little-endian 2-byte hex):
      max_interval = 0x0320 (800 slots = 500 ms)
      min_interval = 0x0320 (800 slots = 500 ms)
      attempt      = 0x0002
      timeout      = 0x0002

    Captures:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Example:
        pytest test_btc_sniff.py::test_raspi_a2dp_sink_C553494
    """
    
    STREAM_PHASE1_DURATION = 120   # seconds - initial streaming
    AVRCP_PAUSE_WAIT       = 120   # seconds - idle time after AVRCP Pause
    STREAM_PHASE3_DURATION = 600   # seconds - streaming after sniff mode disabled (10 min)
    CHECK_INTERVAL         = 60    # seconds - logging tick

    logger().info("\n" + "=" * 70)
    logger().info("   RASPI A2DP SINK - STREAMING AFTER SNIFF MODE DISABLED TEST")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_avrcp_pause"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file  = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename  = f"{test_case_name}_{timestamp}.btsnoop"

    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_sniff_{test_case_name}_{timestamp}")
    logger().info("Frontline sniffer: initialized and capture started")

    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
            logger().info(f"btmon logging STARTED: {bt_mon_log_file}")
            if btsnoop_file:
                logger().info(f"btsnoop capture STARTED: {btsnoop_file}")

            logger().info("\n\n **** set sleep to initialize dut ****\n\n")
            time.sleep(30)

            raspi_bt = bt_client.interfaces.bluetooth

            # Initialize Raspi as A2DP Sink
            raspi_address = raspi_bt.start_a2dp_sink_with_bluez(
                bt_dut_address=None,
                pin_code="0000"
            )
            time.sleep(5)

            wifi_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 60 seconds")
            time.sleep(60)
            logger().info(" Delay completed, now connecting from DUT to Raspi")

            wifi_dut.interfaces.wifi.bt_connect(raspi_address)
            time.sleep(60)

            serial_conn = wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")

            assert any(
                f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "Authentication not complete"
            assert any(
                "a2dp conn ok" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP connection not successful"

            assert any(
                f"A2DP Source start event: {raspi_address}" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP Source start event not received after connect (streaming did not start)"
            assert any(
                "A2DP audio" in line.decode(errors="ignore")
                for ts, line in input_log
            ), "A2DP audio marker not received after connect (streaming did not start)"
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio confirmed after connect")

            # Retrieve DUT BT address dynamically via CLI (cached across test cases)
            dut_bt_address = get_dut_address(wifi_dut)

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info(f"   DUT BT ADDRESS:   {dut_bt_address}")
            logger().info("=" * 70)
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture on Raspi
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # ------------------------------------------------------------------
            # Phase 1: Stream audio for 120 seconds
            # ------------------------------------------------------------------
            logger().info(f"Phase 1: Streaming audio for {STREAM_PHASE1_DURATION} seconds...")
            elapsed = 0
            while elapsed < STREAM_PHASE1_DURATION:
                remaining = STREAM_PHASE1_DURATION - elapsed
                logger().info(f"[Phase 1 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 2: AVRCP Pause → assert pause/suspend events → wait 40 s
            #           → enable Sniff Mode from Raspi → wait remaining 80 s
            #           (total pause window = 120 s)
            # ------------------------------------------------------------------
            logger().info("Phase 2: Initiating AVRCP Pause...")
            pause_result = wifi_dut.interfaces.wifi.bt_avrcp_pause(raspi_address)
            logger().info(f"AVRCP Pause command sent. Result: {pause_result}")

            # Wait briefly for AVRCP pause and A2DP suspend events to arrive on serial
            PAUSE_EVENT_SETTLE  = 5    # seconds to let pause/suspend events appear
            SNIFF_TRIGGER_AFTER = 40   # seconds after pause before sniff mode is enabled
            SNIFF_REMAINING     = AVRCP_PAUSE_WAIT - SNIFF_TRIGGER_AFTER  # 80 s

            logger().info(f"Phase 2: Waiting {PAUSE_EVENT_SETTLE} seconds for pause/suspend events...")
            time.sleep(PAUSE_EVENT_SETTLE)

            # Read fresh serial log slice and assert AVRCP Pause + A2DP Suspend events
            pause_event_log = serial_conn.get_input_log()
            pause_event_lines = [
                line.decode(errors="ignore")
                for ts, line in pause_event_log
            ]
            for pl in pause_event_lines:
                logger().info(f"PAUSE_EVENT_LOG: {pl}")

            assert any("avrcp pause event" in pl for pl in pause_event_lines), (
                "AVRCP Pause event not received on DUT serial log after bt_avrcp_pause command"
            )
            logger().info("ASSERT PASSED: AVRCP Pause event confirmed in serial log")

            assert any(
                f"A2DP Source suspend event: {raspi_address}" in pl
                for pl in pause_event_lines
            ), (
                f"A2DP Source suspend event for {raspi_address} not received on DUT serial log"
            )
            logger().info("ASSERT PASSED: A2DP Source suspend event confirmed in serial log")

            logger().info(
                f"Phase 2: Waiting remaining {SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE} seconds before enabling Sniff Mode..."
            )
            time.sleep(SNIFF_TRIGGER_AFTER - PAUSE_EVENT_SETTLE)

            logger().info("Phase 2: Enabling Sniff Mode from Raspi side...")
            raspi_bt.hci_tool_manager.sniff_mode(
                dev_addr=dut_bt_address,
                sniff_mode_params="0x20 0x03 0x20 0x03 0x02 0x00 0x02 0x00"
            )
            logger().info(f"Sniff Mode enabled from Raspi for DUT {dut_bt_address}")

            # Wait briefly for DUT to report the mode change event on serial
            SNIFF_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 2: Waiting {SNIFF_EVENT_SETTLE} seconds for Sniff Mode event on DUT...")
            time.sleep(SNIFF_EVENT_SETTLE)

            # Read fresh serial log slice and assert SNIFF_MODE_ENABLED event
            sniff_event_log = serial_conn.get_input_log()
            sniff_event_lines = [
                line.decode(errors="ignore")
                for ts, line in sniff_event_log
            ]
            for sl in sniff_event_lines:
                logger().info(f"SNIFF_EVENT_LOG: {sl}")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_ENABLED" in sl
                for sl in sniff_event_lines
            ), (
                f"SNIFF_MODE_ENABLED event for {raspi_address} not received on DUT serial log "
                "after Raspi-side sniff mode command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_ENABLED event confirmed in serial log")

            sniff_idle = SNIFF_REMAINING - SNIFF_EVENT_SETTLE
            logger().info(f"Phase 2: Waiting remaining {sniff_idle} seconds in Sniff Mode...")
            elapsed = 0
            while elapsed < sniff_idle:
                remaining = sniff_idle - elapsed
                logger().info(f"[Phase 2 - Sniff] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # ------------------------------------------------------------------
            # Phase 3: AVRCP Play → assert play + sniff disabled events
            #           → FOCUS: stream for 10 minutes (600 s) after sniff disabled
            # ------------------------------------------------------------------
            logger().info("Phase 3: Initiating AVRCP Play...")
            play_result = wifi_dut.interfaces.wifi.bt_avrcp_play(raspi_address)
            logger().info(f"AVRCP Play command sent. Result: {play_result}")

            # Wait briefly for AVRCP Play triggered and SNIFF_MODE_DISABLED events to arrive
            PLAY_EVENT_SETTLE = 5  # seconds
            logger().info(f"Phase 3: Waiting {PLAY_EVENT_SETTLE} seconds for play/sniff-disabled events...")
            time.sleep(PLAY_EVENT_SETTLE)

            # Read fresh serial log slice and assert both events
            play_event_log = serial_conn.get_input_log()
            play_event_lines = [
                line.decode(errors="ignore")
                for ts, line in play_event_log
            ]
            for pl in play_event_lines:
                logger().info(f"PLAY_EVENT_LOG: {pl}")

            assert any(
                f"AVRCP Play triggered: {raspi_address}" in pl for pl in play_event_lines
            ), (
                f"AVRCP Play triggered event for {raspi_address} not received on DUT serial log "
                "after bt_avrcp_play command"
            )
            logger().info("ASSERT PASSED: AVRCP Play triggered event confirmed in serial log")

            assert any(
                f"mode change event : str_conn_bd_addr : {raspi_address} : SNIFF_MODE_DISABLED" in pl
                for pl in play_event_lines
            ), (
                f"SNIFF_MODE_DISABLED event for {raspi_address} not received on DUT serial log "
                "after AVRCP Play command"
            )
            logger().info("ASSERT PASSED: SNIFF_MODE_DISABLED event confirmed in serial log")

            # 'A2DP Source start event' and 'A2DP audio' also appear from the
            # Phase-1 start and get_input_log() is cumulative, so require a 2nd
            # occurrence to prove streaming actually resumed after Sniff disable.
            start_evt_count = sum(
                pl.count(f"A2DP Source start event: {raspi_address}") for pl in play_event_lines
            )
            a2dp_audio_count = sum(pl.count("A2DP audio") for pl in play_event_lines)
            assert start_evt_count >= 2, (
                "A2DP Source start event did not repeat after AVRCP Play "
                f"(expected >=2, found {start_evt_count}); streaming may not have resumed"
            )
            assert a2dp_audio_count >= 2, (
                "A2DP audio marker did not repeat after AVRCP Play "
                f"(expected >=2, found {a2dp_audio_count}); streaming may not have resumed"
            )
            logger().info("ASSERT PASSED: A2DP Source start + A2DP audio resumed after Sniff Mode disabled")

            # FOCUS: stream audio for 10 minutes (600 s) after Sniff Mode is disabled
            stream3_remaining = STREAM_PHASE3_DURATION - PLAY_EVENT_SETTLE
            logger().info(f"Phase 3: Streaming for {stream3_remaining} seconds after Sniff Mode disabled...")
            elapsed = 0
            while elapsed < stream3_remaining:
                remaining = stream3_remaining - elapsed
                logger().info(f"[Phase 3 - Streaming] {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(CHECK_INTERVAL, remaining))
                elapsed += CHECK_INTERVAL

            # Check audio file size
            try:
                captured_audio_size = raspi_bt.bt_service.read_file_size(capture_file_path)
                logger().info(f"Captured audio size: {captured_audio_size} bytes")
            except Exception as e:
                logger().warning(f"Could not read audio file: {e}")

            # Disconnect the DUT from the Raspi before closing the local stack
            logger().info("Disconnecting DUT from Raspi...")
            wifi_dut.interfaces.wifi.bt_disconnect(raspi_address)
            time.sleep(5)

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs:  {bt_mon_log_file}")
            logger().info(f"Audio file:  {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        btsnoop_file = btsnoop_manager.stop_capture()
        try:
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
        except Exception as sniffer_err:
            logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)

    # Wait between test cases only when running the full test plan
    inter_test_wait(request)
