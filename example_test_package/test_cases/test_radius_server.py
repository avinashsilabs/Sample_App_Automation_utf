import pytest
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def test_radius_server(radius_server):
    logger().info(f" Radius Server test")