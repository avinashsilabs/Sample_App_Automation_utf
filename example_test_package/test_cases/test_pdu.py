import time

from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


def test_verify_pdu(wifi_access_point, wifi_dut, switch):
    switch.interfaces.pdu_switch.turn_on()
    time.sleep(5)
    switch.interfaces.pdu_switch.turn_off()

def test_pdu_switch(wifi_access_point):
   # Point access point to switch_ap in harness
   wifi_access_point.interfaces.wifi.switch.turn_on(delay=5)
   state = wifi_access_point.interfaces.wifi.switch.get_state()
   logger().info("pdu switch state : " + str(state))
   wifi_access_point.interfaces.wifi.switch.turn_off(delay=5)
   state = wifi_access_point.interfaces.wifi.switch.get_state()
   logger().info("pdu switch state : " + str(state))
