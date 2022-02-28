from utf.utils.logger import get_logger
import paramiko
import os

def logger():
    return get_logger(__name__)


def test_capture_power_meter_data_points_to_file(power_meter):
    # Initialize Instrument
    power_meter.interfaces.power_meter.initialize_instrument()
    # Enable voltage measure on channel 3
    power_meter.interfaces.power_meter.enable_voltage_measure(3)
    # Enable current measure on channel 3
    power_meter.interfaces.power_meter.enable_current_measure(3)
    # Set sample period as 0.001
    power_meter.interfaces.power_meter.set_sample_period(3, 0.001)
    # Trigger source and Elog
    power_meter.interfaces.power_meter.configure_trigger_source_and_trigger_elog(3)
    # Capture data for time span of 10 seconds on channel 3
    captured_file_name = power_meter.interfaces.power_meter.capture_data_log(3, 10)
    # Stop data log
    power_meter.interfaces.power_meter.stop_data_log(3)
    file_size = os.path.getsize(captured_file_name)
    assert file_size > 0

