import time
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band, RS9116CoexMode, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116PowerSaveModes
from utf_wiseconnect.utils.rs911x_version import parse_version, extract_version
from utf.utils.time_measurer import TimeMeasurer
import pytest
from utf.utils.logger import get_logger
from utf import UtfDatabaseProperties


def logger():
    return get_logger(__name__)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='wifi_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]


@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_version1',
                                                       test_case_id='test_version1::1',
                                                       notes='test notes'))
def test_btc(wifi_dut):
    result = wifi_dut.interfaces.wifi.btc()
    logger().info(f"Result : {result}")
   


