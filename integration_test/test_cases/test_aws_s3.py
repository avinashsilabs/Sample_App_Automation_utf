import pytest
@pytest.mark.test_src_map_id('SM11759')
def test_upload(aws_s3):
    status = aws_s3.interfaces.s3.upload_file('/app/manifest/RS9116W.2.7.0.6.rps',
                                                           "utf-test", "RS9116W.2.7.0.6.rps")
    assert status is True


@pytest.mark.test_src_map_id('SM11764')
def test_delete(aws_s3):
    status = aws_s3.interfaces.s3.delete_file("utf-test", "RS9116W.2.7.0.6.rps")
    assert status is True


@pytest.mark.test_src_map_id('SM11768')
def test_s3_url(aws_s3):
    url = aws_s3.interfaces.s3.get_file_url("utf-test", "us-east-1", "RS9116W.2.7.0.6.rps")
    assert url == "https://utf-test.s3.us-east-1.amazonaws.com/RS9116W.2.7.0.6.rps"
