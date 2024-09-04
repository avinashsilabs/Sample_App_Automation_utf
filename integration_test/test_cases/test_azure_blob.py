import pytest


def test_upload_file(azure_blob, logger):
    url = azure_blob.interfaces.blob.upload_file('/app/manifest/RS9116W.2.9.1.12.rps', "utf-test_azure")
    logger.info(f"azure url is {url}")
    assert url is not None
