from utf.utils.logger import get_logger
import paramiko
import os
import pytest

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

# TODO: This test is just to make sure keysight power meter data logger is working with WinRM via cli. we will modify this wrt WCF Interface
@pytest.mark.power_meter("keysight_power_analyzer_winRM")
def test_keysight_BenchVue_power_meter(power_meter):  
    # configure input parameters of keysightBenchVue DataLogger
    power_meter.interfaces.power_meter.init_data_log_input_configuration()
    # channel from which power numbers should read as output
    power_meter.interfaces.power_meter.configure_output_chanels([1,2])
    # start power meter bench vue data loggger.
    # TODO This is printing throughput in console log, need to capture this in object while changing interface from WinRM to WCF Service 
    power_meter.interfaces.power_meter.start_keysight_benchvue_data_logger()
