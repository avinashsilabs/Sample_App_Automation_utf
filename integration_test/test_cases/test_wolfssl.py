import time

def test_wolfssl_server(wolfssl, logger):
    # Start the wolfssl server
    wolfssl.interfaces.server.start()
    time.sleep(1)
    assert wolfssl.interfaces.server.is_running() is True
    messages = wolfssl.interfaces.server.get_messages()
    assert len(messages) > 1
    logger.info(messages)

    wolfssl.interfaces.client.start()
    time.sleep(1)
    # Client will disconnect automatically after connecting to server and transferring data.This will ensure client is able to connect to server
    assert wolfssl.interfaces.client.is_running() is False
    messages = wolfssl.interfaces.client.get_messages()
    assert len(messages) > 1
    logger.info(messages)

    assert wolfssl.interfaces.server.is_running() is True
    messages = wolfssl.interfaces.server.get_messages()
    assert len(messages) > 1
    logger.info(messages)

    # Stop the wolfssl server
    wolfssl.interfaces.server.stop()
    time.sleep(1)
    assert wolfssl.interfaces.server.is_running() is False





   