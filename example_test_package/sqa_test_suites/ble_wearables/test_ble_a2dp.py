"""
####################################################################
                    Raspi A2DP Sink Audio Capture Test

                    Setup Requirements:
                    1. Raspberry Pi 4 (as A2DP Sink)
                    2. DUT (RS9116/916)
                    3. btmon for HCI logging, btsnoop binary capture

                    Description:
                    Raspi advertises as A2DP Sink. The DUT connects and streams
                    audio to the Raspi. Two capture artifacts are produced:
                      - btmon text log  (HCI traffic)
                      - btsnoop binary  (raw HCI capture, Wireshark-readable)

                    Author: Ashish Chittimilla
####################################################################
"""
import os
import time
import datetime
import subprocess
import statistics
import pytest
import csv
import shutil
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from datetime import timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf_wiseconnect.interfaces.cli.rs_sapi_rt595_commands import RSSAPIRT595Commands #line added
from utf_wiseconnect_3.tests.devices.si91x import Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.stopwatch import Stopwatch
import re

def logger():
    return get_logger(__name__)


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
# Raspi A2DP Sink - Capture btmon + btsnoop while DUT streams audio
# =============================================================================

def test_raspi_a2dp_sink_C553527(bt_client, wifi_dut):
    """
    Raspi A2DP Sink with customizable duration via environment variable.

    Captures ONLY:
      - btmon text log  (HCI traffic)
      - btsnoop binary  (raw HCI capture for Wireshark/tshark)

    Set AUDIO_CAPTURE_DURATION environment variable (in seconds) before running.
    Default: 600 seconds (10 minutes)

    Example:
        SET AUDIO_CAPTURE_DURATION=900
        pytest test_ble_a2dp.py::test_raspi_a2dp_sink_C553527
    """
    # Get duration from environment variable or use default
    wait_duration = int(os.environ.get("AUDIO_CAPTURE_DURATION", "600"))

    logger().info("\n" + "=" * 70)
    logger().info(f"   RASPI A2DP SINK - CUSTOM DURATION ({wait_duration // 60} MINUTES)")
    logger().info("=" * 70 + "\n")

    test_case_name = "raspi_a2dp_sink_custom"

    # Generate file paths with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file = f"reports/{test_case_name}_btmon_{timestamp}.log"
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    btsnoop_filename = f"{test_case_name}_{timestamp}.btsnoop"

    # Create btsnoop capture manager (binary capture for later Wireshark/tshark)
    btsnoop_manager = BtsnoopCaptureManager(output_dir="reports")

    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)

    # Assert btsnoop/btmon binary capture actually started. start_capture()
    # returns None if the subprocess could not be launched.
    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    # Guard against btmon dying immediately after launch (e.g. sudo prompt,
    # no HCI device). poll() is None only while the process is still running.
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."

    # Wrap the whole streaming flow in try/finally so the btsnoop binary
    # capture is ALWAYS stopped, even if an assertion fails mid-test.
    # Without this, the detached 'btmon -w' process (start_new_session=True)
    # would be left hanging as an orphan on the Raspi.
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

            serial_conn = wifi_dut.interfaces.wifi.bus  # HostSerialConnectionAsync
            input_log = serial_conn.get_input_log()
            # Print all lines captured from serial log for debugging
            for ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                logger().info(f"SERIAL_LOG: {decoded_line}")
            # Assert the presence of the string in any line
            assert any(f"auth_complete event: bd_addr {raspi_address}" in line.decode(errors="ignore") for ts, line in input_log), "Authentication not complete"
            assert any("a2dp conn ok" in line.decode(errors="ignore") for ts, line in input_log), "A2DP connection not successful"

            logger().info("=" * 70)
            logger().info(f"   RASPI BT ADDRESS: {raspi_address}")
            logger().info("=" * 70)
            logger().info(f"   Session duration: {wait_duration} seconds ({wait_duration // 60} minutes)")
            logger().info("   btmon + btsnoop capture: ENABLED")
            logger().info("=" * 70)

            # Start audio capture
            raspi_bt.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            # Wait for connection and audio streaming
            logger().info(f"Waiting {wait_duration} seconds for connection and audio...")
            logger().info("")

            # Wait with periodic updates
            check_interval = 60
            elapsed = 0
            while elapsed < wait_duration:
                remaining = wait_duration - elapsed
                logger().info(f"Waiting... {elapsed}s elapsed, {remaining}s remaining")
                time.sleep(min(check_interval, remaining))
                elapsed += check_interval

            # Check audio file
            try:
                captured_audio_size = raspi_bt.bt_service.read_file_size(capture_file_path)
                logger().info(f"Captured audio size: {captured_audio_size} bytes")
            except Exception as e:
                logger().warning(f"Could not read audio file: {e}")

            # Cleanup
            raspi_bt.close()

            logger().info("=" * 70)
            logger().info(f"btmon logs: {bt_mon_log_file}")
            logger().info(f"Audio file: {capture_file_path}")
            if btsnoop_file:
                logger().info(f"btsnoop file: {btsnoop_file}")
            logger().info("=" * 70)
    finally:
        # Always stop btsnoop capture so btmon is never left hanging, even on failure
        btsnoop_file = btsnoop_manager.stop_capture()

    logger().info("=" * 70)
    logger().info("   OUTPUT FILES")
    logger().info("=" * 70)
    logger().info(f"   btmon log:      {bt_mon_log_file}")
    logger().info(f"   Audio WAV:      {capture_file_path}")
    logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
    logger().info("=" * 70)
