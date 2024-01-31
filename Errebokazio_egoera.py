
#from scapy import ansmachine as AnsweringMachine
import sys
from scapy.ansmachine import AnsweringMachine
from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet

from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.fields import *
import requests
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

#DTLS PAKETEAREN ESTRUKTURA
from scapy.layers.l2 import Ether

#********DTLS HEADER******************
class DTLS(Packet):
    name = "DTLS"
    fields_desc = [
        BitField('contentType', 0, 8),
        BitField('version', 0, 16),
        BitField('epoch', 0, 16),
        BitField('seqNumber', 0, 48),
        BitField('length', 0, 16),
        BitField('sh', 0, 8)
    ]
#*************************Interfazeak lortu************************
def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        #print(i)
        if "eth0" in i:
            iface=i
            print(iface)
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


#*********************CRL JAITSI*************************************
def get_crl():
    URL = "http://10.0.4.4:80/CAroot.crl.pem"
    file = requests.get(URL, stream = True)
    with open("CAroot.crl.pem","wb") as pem:
        for chunk in file.iter_content(chunk_size=1024):
             if chunk:
                pem.write(chunk)

#******************ZERBITZARIAREN ZIURTAGIRIA CRLan DAGO?**********
def check_certificate(server_serial_number):

    crl_data = open("CAroot.crl.pem","rb").read() #CRL fitxategi sistematik lortu
    crl = x509.load_pem_x509_crl(crl_data,backend=default_backend())


    #CRL objektua sortu
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(crl.issuer) #CRLaren hornitzaile izena
    builder = builder.last_update(crl.last_update) #CRLaren azken aldaketa

    #CRL ziurtagiriak fitxategitik objektura pasa
    for i in range(0,len(crl)):
        builder = builder.add_revoked_certificate(crl[i])
        print(crl[i].serial_number)
    #Konprobatu ea ziurtagiria crl zerrendan dagoen
    konprobazioa = crl.get_revoked_certificate_by_serial_number(server_serial_number)

    #Badago? Bai--> Konexioa errefustu//Ez, segi
    if not  isinstance(konprobazioa, x509.RevokedCertificate):
        print("EZ dago")
        konp = 1
    else:
        print("DAGO")
        konp = 2

    return konp


#PAKETEAREN MANIPULAZIOA
paketeak = []
def paketea_manipulatu(paketea):

    pakete = bytes(paketea) #Jasotako paketea byte-tara pasatu
    eth_h = None
    ip_h = None
    udp_h = None
    dtls_h = None
    dtls_h2 = None
    global konp

    #PAKETEAREN ETHERNET EREMUA
    ETHERNET_HEADER = 14
    ETHERNET_OFFSET = 0 + ETHERNET_HEADER
    eth_h = Ether(pakete[0:ETHERNET_OFFSET])
    #eth_h.show()

    #PAKETEAREN IP EREMUA
    IP_HEADER = 20
    IP_OFFSET= ETHERNET_HEADER + IP_HEADER
    ip_h = IP(pakete[ETHERNET_OFFSET:IP_OFFSET])
    # ip_h.show()

    #PAKETEAREN UDP EREMUA
    UDP_HEADER = 8
    UDP_OFFSET = IP_OFFSET + UDP_HEADER
    udp_h = UDP(pakete[IP_OFFSET:UDP_OFFSET])
    # udp_h.show()

    #PAKETE DTLS
    DTLS_HEADER = UDP_OFFSET + 14
    dtls_h = DTLS(pakete[UDP_OFFSET:DTLS_HEADER])
    # dtls_h.show()

    #PAKETEAREN DTLS EREMUA (SERVER HELL0)
    DTLS_OFFSET_SH = UDP_OFFSET + 86 #Server Hello tamaina --> 86 byte (Wiresharken begiratuta)


    # PAKETEAREN DTLS EREMUA (SERVER HELL0)
    DTLS_OFFSET_CERT = DTLS_OFFSET_SH + 14 + 14 + 30
    dtls_h2 = DTLS(pakete[DTLS_OFFSET_SH:DTLS_OFFSET_CERT])
    #dtls_h2.show()

    #ZIURTAGIRI EREMU BYTEAK
    CERT_SERIALNUM_START = DTLS_OFFSET_SH + 14 + 14 + 18
    CERT_SERIALNUM_END = CERT_SERIALNUM_START + 1
    SERVER_SERIAL_NUM = bytes(pakete[CERT_SERIALNUM_START:CERT_SERIALNUM_END]) #ZERBITZARIAREN SERIE ZENBAKIA
    #print(SERVER_SERIAL_NUM)



    #ZIURTAGIRIEN KONPROBAKETA
    if udp_h.sport == 28000 and len(paketeak) < 3:
        print("PAKETEA JASO DA")
        if dtls_h.sh == 0x02 or dtls_h.sh == 0x0b:
            if dtls_h.sh == 0x02:
                print("0X02 heldu da")
                # ZERBITZARIAREN SERIE ZENBAKIA INT
                server_sn = int.from_bytes(SERVER_SERIAL_NUM, "big")
                # print("SERIE ZENBAKIAAAAAAAAAAAAAAAAAAAA")
                print(server_sn)

                get_crl()
                konp = check_certificate(server_sn)
                if konp == 1:
                    iface = get_if()
                    print("ZIURTAGIRIA SEGURUA DA ETA EZ DAGO CRL ZERRENDAN")
                    bidaltzeko_pak = pakete
                    paketeak.append(bidaltzeko_pak)
                    sendp(bidaltzeko_pak,iface=iface)
                    print("SH PAK BIDALI DA")
                else:
                    print("ZIURTAGIRIA EZ DA SEGURUA")

            if dtls_h.sh == 0x0b and konp == 1:
                print("0X0b heldu da")
                iface = get_if()
                bidaltzeko_pak = pakete
                paketeak.append(bidaltzeko_pak)
                sendp(bidaltzeko_pak, iface=iface)
                print("CERT ETA SHD PAK BIDALI DA")
    print("//////////////////////////////////////////////////////////////")



def main():
    interface = get_if() #interfazea lortu
    print("sniffing on %s" % interface)
    sys.stdout.flush()
    sniff(iface = interface, prn = lambda x: paketea_manipulatu(x))

if __name__ == '__main__':
    main()


