from utf.interfaces.spectrum_analyzer.keysight_spectrum_analyzer import PowerUnits, TraceTypes
from utf.utils.logger import get_logger
import paramiko
import os
import pytest
from utf.utils import print_dict
import time

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)

@pytest.mark.spectrum_analyzer("keysight_spectrum_analyzer")
def test_measure_channel_power(spectrum_analyzer):
    # Initialize Instrument
    spectrum_analyzer.interfaces.spectrum_analyzer.initialize_instrument()
   
        
    # Optional: Set power units (default is usually DBM)
    spectrum_analyzer.interfaces.spectrum_analyzer.set_power_units(PowerUnits.DBM)
    
    # Configure and measure channel power with specified parameters
    measurements = spectrum_analyzer.configure_and_measure_channel_power(
        center_frequency="51 MHz",
        span="11 MHz",
        integration_bandwidth="20MHz",
        average_count=20,
        trace_type=TraceTypes.AVERAGE,
        averaging_on=True,
        return_all_measurements=True
        
    )
    assert measurements["channel_power"] is not None
    __print_throughput(measurements)
    

