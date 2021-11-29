from utils.logger import get_logger


def logger():
    return get_logger(__name__)


def test_capture_to_file(wifi_logic_analyzer):
    wifi_logic_analyzer.interfaces.logic_analyzer.capture_to_file('/home/test/test5.logicdata')