import pytest
from utf import UtfDatabaseProperties


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
                                                       test_case_name='test_db_props',
                                                       test_case_id='test_db_props::1',
                                                       notes='test test_db_props'))
def test_db_props(wifi_dut):
    assert True


@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_block_db',
                                                       test_case_id='test_block_db::1',
                                                       notes='test test_block_db'))
@pytest.mark.skipif(True, reason='blocked')
def test_block_db():
    assert True
