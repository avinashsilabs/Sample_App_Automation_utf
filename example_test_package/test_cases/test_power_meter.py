from utf.utils.logger import get_logger
import paramiko
import os
import pytest
from utf.utils.iperf.iperf_utils import print_dict

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


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

@pytest.mark.power_meter("keysight_benchvue_power_analyzer_win_wcf")
def test_power_meter_keysight_benchvue_win_wcf(power_meter):
    # Init power meter by specifying module name as datalogger or scope
    power_meter.interfaces.power_meter.init_power_meter(data_log_file_name="UTF1_Data_Log")
    # Init power meter module 
    power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
    # set power meter out put channels
    power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "1", "emulation_mode": "Current", "measure_voltage": True, "measure_current": True},{"channel": "2", "emulation_mode": "current", "measure_voltage": True, "measure_current": True}])
    # switching On channels
    #power_meter.interfaces.power_meter.turn_on_channels(["1","2"])
    # start capture power meter datalog/scope
    power_meter.interfaces.power_meter.start_capture()
    
    # Parse result as throughput object
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None 
    

@pytest.mark.power_meter("keysight_benchvue_power_analyzer_win_rm")
def test_power_meter_keysight_benchvue_win_rm(power_meter):
    # Init power meter as datalogger/scope
    power_meter.interfaces.power_meter.init_power_meter()
    # Init power meter module 
    power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
    # set power meter out put channels
    power_meter.interfaces.power_meter.set_output_channels(["1","2"])
    # start capture power meter datalog/scope
    power_meter.interfaces.power_meter.start_capture()
     
    # Parse result as throughput object
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None 
   
