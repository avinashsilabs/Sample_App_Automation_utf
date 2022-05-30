import time

from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


def test_verify_pdu(wifi_access_point, wifi_dut, switch):
    switch.interfaces.pdu_switch.turn_on()
    time.sleep(5)
    switch.interfaces.pdu_switch.turn_off()

