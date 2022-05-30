from utf.utils.logger import get_logger
from utf.interfaces.pdu_switch import Switch


def logger():
    return get_logger(__name__)

def test_verify_pdu(wifi_access_point, wifi_dut, pdu_switch):
    pdu_switch.interfaces.pdu_switch.turn_on()
    time.sleep(5)
    pdu_switch.interfaces.pdu_switch.turn_off()

