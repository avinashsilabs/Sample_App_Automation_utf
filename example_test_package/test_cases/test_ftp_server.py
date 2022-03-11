from utils.logger import get_logger
import paramiko
import os
def logger():
    return get_logger(__name__)

def test_ftp_server(ftp_server, ftp_client):
    # start FTP server
    ftp_server.interfaces.vsftpd_ftp_server.start_server()
    # connect FTP Client to  FTP Server
    ftp_client.interfaces.ftplib_ftp_client.connect()
    ftp_client.interfaces.ftplib_ftp_client.login()
    ftp_client.interfaces.ftplib_ftp_client.write_to_file()
    ftp_client.interfaces.ftplib_ftp_client.read_from_file()
    ftp_client.interfaces.ftplib_ftp_client.create_dir()
    ftp_client.interfaces.ftplib_ftp_client.remove_dir()
