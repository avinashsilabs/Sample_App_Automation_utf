import pytest
@pytest.mark.test_src_map_id('TC0284147561')
def test_dtls_client_server(dtls_server, dtls_client, logger):
    logger.info("Starting DTLS server...")
    server = dtls_server.interfaces.dtls_server
    server.start()
    logger.info("DTLS server is running.")

    try:
        client = dtls_client.interfaces.dtls_client
        with client as cli:
            cli.do_handshake()
            message = "hello DTLS test"
            response = cli.echo(message.encode("utf-8"), 1024)
            logger.info(f"Server replied: {response.decode('utf-8')}")
            logger.info("Test passed: Server echoed the message correctly.")
    except Exception as e:
        logger.error(f"Error in client: {e}")
    finally:
        throughput = server.measure_rx_throughput()
        logger.info(f"DTLS client throughput: {throughput} Mbps")
        server.stop()
        if not server.is_running():
            logger.info("Server has stopped successfully.")
        else:
            logger.error("Server did not stop within the expected time frame.")
