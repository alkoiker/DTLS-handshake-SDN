from os import path
from datetime import datetime
import ssl
from socket import socket, AF_INET, SOCK_DGRAM
from logging import basicConfig, DEBUG
basicConfig(level=DEBUG)  # set now for dtls import code
from dtls import do_patch
do_patch()


cert_path = path.join(path.abspath(path.dirname(__file__)), "certs")
s = ssl.wrap_socket(socket(AF_INET, SOCK_DGRAM), cert_reqs=ssl.CERT_NONE, ca_certs=path.join(cert_path, "cacert.pem"))
s.connect(('10.0.1.1', 28000))
print("************************************************")
s.send('Hi there'.encode())
print(s.recv().decode())
s = s.unwrap()
s.close()

pass

