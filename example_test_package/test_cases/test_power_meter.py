from utils.logger import get_logger
import paramiko
import os

def logger():
    return get_logger(__name__)


def test_capture_power_meter_data_points_to_file(power_meter):
    power_meter.interfaces.power_meter.initialize_instrument()
    power_meter.interfaces.power_meter.enable_voltage_measure(3, power_meter.interfaces.power_meter._inst)
    power_meter.interfaces.power_meter.enable_current_measure(3, power_meter.interfaces.power_meter._inst)
    power_meter.interfaces.power_meter.set_sample_period(3, power_meter.interfaces.power_meter._inst, 0.001)
    power_meter.interfaces.power_meter.configure_trigger_source_and_trigger_elog(3, power_meter.interfaces.power_meter._inst)
    power_meter.interfaces.power_meter.capture_data_log(3, power_meter.interfaces.power_meter._inst)
    power_meter.interfaces.power_meter.stop_data_log(3, power_meter.interfaces.power_meter._inst)
