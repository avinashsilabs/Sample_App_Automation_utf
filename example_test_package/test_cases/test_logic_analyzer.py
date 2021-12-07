from utils.logger import get_logger
import paramiko
import os

def logger():
    return get_logger(__name__)


def test_capture_to_file(logic_analyzer):
    digital = [0,1,2,3,4]
    analog = [0,1]
    # set active channels
    logic_analyzer.interfaces.logic_analyzer.set_active_channels(digital, analog)
    # get available sample rates
    sample_rate_tuple = logic_analyzer.interfaces.logic_analyzer.saleae_logic_analyzer_instance.get_all_sample_rates()
    # set number of samples
    logic_analyzer.interfaces.logic_analyzer.set_num_samples(2e6)
    # set sample rates
    logic_analyzer.interfaces.logic_analyzer.set_sample_rate(sample_rate_tuple[0])
    # set sample time
    logic_analyzer.interfaces.logic_analyzer.set_capture_seconds(0.0001)
    # capture to file. specify file name. this will geenrate file app/reports
    captured_file_name = logic_analyzer.interfaces.logic_analyzer.capture_to_file('logic_analyzer_test')
    file_size = os.path.getsize(captured_file_name)
    assert file_size > 0
