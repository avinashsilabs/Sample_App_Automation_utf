from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def test_create_presigned_url(aws_s3):
    presigned_url = aws_s3.interfaces.s3.create_presigned_url("utf-test", "RS9116W.2.7.0.6.rps", 43200)
    logger().info(f"created presigned url is: {presigned_url}")
    assert presigned_url is not None