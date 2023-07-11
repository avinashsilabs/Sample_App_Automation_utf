from utf.utils.logger import get_logger
import paramiko
import os
import pytest
from utf.utils.iperf.iperf_utils import print_dict
import time

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)

@pytest.mark.power_meter("keysight_N6705_power_analyzer")
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
    captured_file_name = power_meter.interfaces.power_meter.start_capture(3, 10)
    # Stop data log
    power_meter.interfaces.power_meter.stop_capture(3)
    file_size = os.path.getsize(captured_file_name)
    assert file_size > 0

def test_power_meter_keysight_benchvue_win_wcf(power_meter):
    # Init power meter by specifying module name as datalogger or scope
    power_meter.interfaces.power_meter.init_power_meter(data_log_file_name="UTF1_Data_Log")
    # Init power meter module 
    power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
    # set power meter out put channels
    power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_power": True},{"channel": "2", "emulation_mode": "Voltage Measure", "trace_voltage": True, "trace_current": False, "trace_power": True}])
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
   
def test_power_meter_using_nrf_ppk(power_meters):
    # Initialize Instrument
    power_meters[0].interfaces.power_meter.initialize_instrument()
    
    # Turn on DUT
    power_meters[0].interfaces.power_meter.turn_on_DUT_power()
    
    # Start Capture 
    power_meters[0].interfaces.power_meter.start_capture()
    for _ in range(30):
        logger().info("Do Some Thing")
        time.sleep(1)
    # Stop Capture 
    power_meters[0].interfaces.power_meter.stop_capture()
    file_size = os.path.getsize(power_meters[0].interfaces.power_meter.capture_file)
    assert file_size > 0
    parsed_result = power_meters[0].interfaces.power_meter.process_output()
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None 
    
def test_power_meter_keysight_benchvue_win_wcf_scope(power_meter):
    # Init power meter by specifying module name as datalogger or scope
    power_meter.interfaces.power_meter.init_power_meter()
    # Init power meter module 
    power_meter.interfaces.power_meter.init_power_meter_module("scope")
    # set power meter out put channels
    power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_power": True},{"channel": "2", "emulation_mode": "Voltage Measure", "trace_voltage": True, "trace_current": False, "trace_power": True}])
    # start capture power meter datalog/scope
    power_meter.interfaces.power_meter.start_capture()
    # Parse result as throughput object
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Scp File Name"] is not None
    
def test_power_meter_using_nrf_ppk_mp(power_meters, plotter):
    # Initialize Instrument
    power_meters[0].interfaces.power_meter.initialize_instrument()
    # Turn on DUT
    power_meters[0].interfaces.power_meter.turn_on_DUT_power()
    # Start Capture 
    power_meters[0].interfaces.power_meter.start_capture()
    file_size = os.path.getsize(power_meters[0].interfaces.power_meter.capture_file)
    assert file_size > 0
    parsed_result = power_meters[0].interfaces.power_meter.process_output()
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None 
    power_meters[0].interfaces.power_meter.required_plot = True
    if power_meters[0].interfaces.power_meter.required_plot:
        # Read csv data and store in data frames of plotter
        plotter.interfaces.plotter.read_data_from_csv(file_path = power_meters[0].interfaces.power_meter.capture_file)
        # Draw plot
        plotter.interfaces.plotter.draw_plot()
        # Update data by setting axis
        plotter.interfaces.plotter.update_data()
        # Update plot by setting axies and traces 
        plotter.interfaces.plotter.update_plot()
        # Export plot to html file
        plotter.interfaces.plotter.export_plot_to_html()
        # Assert the generated html file size
        plot_file_size = os.path.getsize(plotter.interfaces.plotter.plot_file_path)
        assert plot_file_size > 0
    