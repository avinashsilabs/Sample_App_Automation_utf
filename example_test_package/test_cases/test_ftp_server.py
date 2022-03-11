import pytest

def test_ftp_server(ftp_server, ftp_client):
    # start FTP server
    ftp_server.interfaces.vsftpd_ftp_server.start_server()
    # connect FTP Client to  FTP Server
    ftp_client.interfaces.ftplib_ftp_client.connect()
    # login to FTP server
    ftp_client.interfaces.ftplib_ftp_client.login()
    # write file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.write_to_file()
    # read file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.read_from_file()
    # create dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.create_dir()
    # remove dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.remove_dir()

@pytest.mark.config("ftp_server", vsftpd_ftp_server={"tls_enabled": True})
@pytest.mark.config("ftp_client", ftplib_ftp_client={"tls_enabled": True})
def test_ftp_server_tls(ftp_server, ftp_client):
    # start FTP server
    ftp_server.interfaces.vsftpd_ftp_server.start_server()
    # connect FTP Client to  FTP Server
    ftp_client.interfaces.ftplib_ftp_client.connect()
    # login to FTP server
    ftp_client.interfaces.ftplib_ftp_client.login()
    # write file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.write_to_file()
    # read file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.read_from_file()
    # create dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.create_dir()
    # remove dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.remove_dir()
