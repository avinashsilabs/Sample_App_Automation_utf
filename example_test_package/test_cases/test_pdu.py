import time

from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


def test_verify_pdu(wifi_access_point, wifi_dut, switch):
    switch.interfaces.pdu_switch.turn_on()
    time.sleep(5)
    switch.interfaces.pdu_switch.turn_off()

def test_pdu_switch_state(wifi_access_point):
   # Point access point to switch_ap in harness
   wifi_access_point.interfaces.wifi.switch.turn_on(delay=5)
   state = wifi_access_point.interfaces.wifi.switch.get_state()
   logger().info("pdu switch state : " + str(state))
   assert state == 'true'
   wifi_access_point.interfaces.wifi.switch.turn_off(delay=5)
   state = wifi_access_point.interfaces.wifi.switch.get_state()
   logger().info("pdu switch state : " + str(state))
   assert state == 'false'
   
def test_pdu_switches(switches):
   # swtich #1
    switches[0].interfaces.pdu_switch.turn_on()
    state = switches[0].interfaces.pdu_switch.get_state()
    logger().info("pdu switch one state : " + str(state))
    assert state == 'true'
    time.sleep(30)
    switches[0].interfaces.pdu_switch.turn_off()
    state = switches[0].interfaces.pdu_switch.get_state()
    logger().info("pdu switch one state : " + str(state))
    assert state == 'false'
    # swtich #2
    switches[1].interfaces.pdu_switch.turn_on()
    time.sleep(30)
    switches[1].interfaces.pdu_switch.turn_off()
   