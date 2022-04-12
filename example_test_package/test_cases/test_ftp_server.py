import pytest
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def test_ftp_server(ftp_server, ftp_client):
    # login to FTP server
    ftp_client.interfaces.ftplib_ftp_client.login()
    # read file to ftp server 
    assert ftp_client.interfaces.ftplib_ftp_client.read_from_file('readMe.txt') == "This is read me file"
    # write file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.write_to_file('readMe1.txt', "This is read me file1")
    # read file to ftp server
    logger().info(ftp_client.interfaces.ftplib_ftp_client.read_from_file('readMe1.txt'))
    # create dir in ftp server
    assert ftp_client.interfaces.ftplib_ftp_client.create_dir('ftp_dir') == "/ftp_dir"
    # remove dir in ftp server
    assert ftp_client.interfaces.ftplib_ftp_client.remove_dir('ftp_dir') == "250 Remove directory operation successful."

@pytest.mark.ftp_server("raspi_ftp_server_tls")
@pytest.mark.ftp_client("raspi_ftp_client_tls")
def test_ftp_server_tls(ftp_server, ftp_client):
    ftp_client.interfaces.ftplib_ftp_client.login()
    # read file to ftp server 
    assert ftp_client.interfaces.ftplib_ftp_client.read_from_file('readMe.txt') == "This is read me file"
    # write file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.write_to_file('readMe1.txt',"This is read me file1")
    # read file to ftp server
    logger().info(ftp_client.interfaces.ftplib_ftp_client.read_from_file('readMe1.txt'))
    # create dir in ftp server
    assert ftp_client.interfaces.ftplib_ftp_client.create_dir('ftp_dir') == "/ftp_dir"
    # remove dir in ftp server
    assert ftp_client.interfaces.ftplib_ftp_client.remove_dir('ftp_dir') == "250 Remove directory operation successful."
