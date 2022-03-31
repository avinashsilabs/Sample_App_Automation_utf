import pytest

def test_ftp_server(ftp_server, ftp_client):
    # login to FTP server
    ftp_client.interfaces.ftplib_ftp_client.login()
    # write file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.write_to_file('readMe.txt')
    # read file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.read_from_file('readMe.txt')
    # create dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.create_dir('ftp_dir')
    # remove dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.remove_dir('ftp_dir')

@pytest.mark.ftp_server("raspi_ftp_server_tls")
@pytest.mark.ftp_client("raspi_ftp_client_tls")
def test_ftp_server_tls(ftp_server, ftp_client):
    ftp_client.interfaces.ftplib_ftp_client.login()
    # write file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.write_to_file('readMe.txt')
    # read file to ftp server
    ftp_client.interfaces.ftplib_ftp_client.read_from_file('readMe.txt')
    # create dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.create_dir('ftp_dir')
    # remove dir in ftp server
    ftp_client.interfaces.ftplib_ftp_client.remove_dir('ftp_dir')