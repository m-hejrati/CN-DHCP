import socket,sys
import time
import binascii

MAX_BYTES = 1024

SERVER_PORT = 6700
CLIENT_PORT = 6800

client_mac_address = "00:05:3c:04:8d:59"

def discover_get():
    OPCODE          = bytes([0x01])
    HARDWARE_TYPE   = bytes([0x01])
    HARDWARE_LEN    = bytes([0x06])
    HOPS            = bytes([0x00])
    TRANSACTION_ID  = bytes([0x39, 0x03, 0xF3, 0x26])
    SECONDS_ELAPSED = bytes([0x00, 0x00])
    FLAGS           = bytes([0x00, 0x00])
    CLIENT_IP_ADDR  = bytes([0x00, 0x00, 0x00, 0x00])
    YOUR_IP_ADDR    = bytes([0x00, 0x00, 0x00, 0x00])
    SERVER_IP_ADDR  = bytes([0x00, 0x00, 0x00, 0x00])
    GATEWAY_IP_ADDR = bytes([0x00, 0x00, 0x00, 0x00])

    CLIENT_HARD_AD1 = binascii.unhexlify(client_mac_address.replace(':', ''))
    CLIENT_HARD_AD2 = bytes([0x00, 0x00]) 
    
    CLIENT_HARD_AD3 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD4 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD5 = bytes(192)
    Magiccookie     = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1    = bytes([53 , 1 , 1])
    DHCPOptions2    = bytes([50 , 4 , 0xC0, 0xA8, 0x01, 0x64])

    package = OPCODE + HARDWARE_TYPE + HARDWARE_LEN + HOPS + TRANSACTION_ID + SECONDS_ELAPSED + FLAGS \
            + CLIENT_IP_ADDR + YOUR_IP_ADDR + SERVER_IP_ADDR + GATEWAY_IP_ADDR + CLIENT_HARD_AD1 \
            + CLIENT_HARD_AD2 + CLIENT_HARD_AD3 + CLIENT_HARD_AD4 + CLIENT_HARD_AD5 + Magiccookie \
            + DHCPOptions1 + DHCPOptions2

    return package


def request_get():
    OPCODE          = bytes([0x01])
    HARDWARE_TYPE   = bytes([0x01])
    HARDWARE_LEN    = bytes([0x06])
    HOPS            = bytes([0x00])
    TRANSACTION_ID  = bytes([0x39, 0x03, 0xF3, 0x26])
    SECONDS_ELAPSED = bytes([0x00, 0x00])
    FLAGS           = bytes([0x00, 0x00])
    CLIENT_IP_ADDR  = bytes([0x00, 0x00, 0x00, 0x00])
    YOUR_IP_ADDR    = bytes([0x00, 0x00, 0x00, 0x00])
    SERVER_IP_ADDR  = bytes([0x00, 0x00, 0x00, 0x00])
    GATEWAY_IP_ADDR = bytes([0x00, 0x00, 0x00, 0x00])

    CLIENT_HARD_AD1 = binascii.unhexlify(client_mac_address.replace(':', ''))
    CLIENT_HARD_AD2 = bytes([0x00, 0x00]) 

    CLIENT_HARD_AD3 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD4 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD5 = bytes(192)
    Magiccookie     = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1    = bytes([53 , 1 , 3])
    DHCPOptions2    = bytes([50 , 4 , 0xC0, 0xA8, 0x01, 0x64])
    DHCPOptions3    = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01])

    package = OPCODE + HARDWARE_TYPE + HARDWARE_LEN + HOPS + TRANSACTION_ID + SECONDS_ELAPSED + FLAGS \
            + CLIENT_IP_ADDR + YOUR_IP_ADDR + SERVER_IP_ADDR + GATEWAY_IP_ADDR + CLIENT_HARD_AD1 \
            + CLIENT_HARD_AD2 + CLIENT_HARD_AD3 + CLIENT_HARD_AD4 + CLIENT_HARD_AD5 + Magiccookie \
            + DHCPOptions1 + DHCPOptions2 + DHCPOptions3

    return package


def print_mac_address(mac):
    printable_mac = ""
    for i in range(5):
        printable_mac += str(f"{mac[i]:0{2}x}") + ":"
    printable_mac += str(f"{mac[5]:0{2}x}")
    # print(print_mac)
    return printable_mac


def print_ip_address(ip):
    print_ip = str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])
    print(print_ip)
    return print_ip



print("DHCP client is starting...\n")
dest = ('<broadcast>', SERVER_PORT)
# dest = ('127.0.0.1', SERVER_PORT)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(('0.0.0.0', CLIENT_PORT))
# s.bind(('127.0.0.1', CLIENT_PORT))

print("Send DHCP discovery.")
data = discover_get()
s.sendto(data, dest)

data, address = s.recvfrom(MAX_BYTES)
print("Receive DHCP offer.")
#print(data)

print("Send DHCP request.")
data = request_get()
s.sendto(data, dest)
        
data,address = s.recvfrom(MAX_BYTES)
print("Receive DHCP ack.\n")
# print(data)
print("Assigned IP:")
print_ip_address(data[16:20])