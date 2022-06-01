import socket
import json
import time
import pprint

MAX_BYTES = 1024

SERVER_PORT = 6700
CLIENT_PORT = 6800

def offer_get(ip):

    OPCODE          = bytes([0x02])
    HARDWARE_TYPE   = bytes([0x01])
    HARDWARE_LEN    = bytes([0x06])
    HOPS            = bytes([0x00])
    TRANSACTION_ID  = bytes([0x39, 0x03, 0xF3, 0x26])
    SECONDS_ELAPSED = bytes([0x00, 0x00])
    FLAGS           = bytes([0x00, 0x00])
    CLIENT_IP_ADDR  = bytes([0x00, 0x00, 0x00, 0x00])

    spl = ip.split(".")
    YOUR_IP_ADDR    = bytes([int(spl[0]), int(spl[1]), int(spl[2]), int(spl[3])])
    # print(YOUR_IP_ADDR)

    SERVER_IP_ADDR  = bytes([0xC0, 0xA8, 0x01, 0x01]) #192.168.1.1
    GATEWAY_IP_ADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CLIENT_HARD_AD1 = bytes([0x00, 0x05, 0x3C, 0x04]) 
    CLIENT_HARD_AD2 = bytes([0x8D, 0x59, 0x00, 0x00])
    CLIENT_HARD_AD3 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD4 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD5 = bytes(192)
    Magiccookie     = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1    = bytes([53 , 1 , 2]) # DHCP Offer
    DHCPOptions2    =  bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00]) #255.255.255.0 subnet mask
    DHCPOptions3    = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #192.168.1.1 router
    DHCPOptions4    = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80]) #86400s(1 day) IP address lease time
    DHCPOptions5    = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) # DHCP server
    
    package = OPCODE + HARDWARE_TYPE + HARDWARE_LEN + HOPS + TRANSACTION_ID + SECONDS_ELAPSED + FLAGS \
            + CLIENT_IP_ADDR + YOUR_IP_ADDR + SERVER_IP_ADDR + GATEWAY_IP_ADDR + CLIENT_HARD_AD1 \
            + CLIENT_HARD_AD2 + CLIENT_HARD_AD3 + CLIENT_HARD_AD4 + CLIENT_HARD_AD5 + Magiccookie \
            + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

    return package


def pack_get(ip):
    OPCODE          = bytes([0x02])
    HARDWARE_TYPE   = bytes([0x01])
    HARDWARE_LEN    = bytes([0x06])
    HOPS            = bytes([0x00])
    TRANSACTION_ID  = bytes([0x39, 0x03, 0xF3, 0x26])
    SECONDS_ELAPSED = bytes([0x00, 0x00])
    FLAGS           = bytes([0x00, 0x00])
    CLIENT_IP_ADDR  = bytes([0x00, 0x00, 0x00, 0x00])

    spl = ip.split(".")
    YOUR_IP_ADDR    = bytes([int(spl[0]), int(spl[1]), int(spl[2]), int(spl[3])])

    SERVER_IP_ADDR  = bytes([0xC0, 0xA8, 0x01, 0x01]) #192.168.1.1
    GATEWAY_IP_ADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CLIENT_HARD_AD1 = bytes([0x00, 0x05, 0x3C, 0x04]) 
    CLIENT_HARD_AD2 = bytes([0x8D, 0x59, 0x00, 0x00])
    CLIENT_HARD_AD3 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD4 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CLIENT_HARD_AD5 = bytes(192)
    Magiccookie     = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1    = bytes([53 , 1 , 5]) #DHCP ACK(value = 5)
    DHCPOptions2    = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00]) #255.255.255.0 subnet mask
    DHCPOptions3    = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #192.168.1.1 router
    DHCPOptions4    = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80]) #86400s(1 day) IP address lease time
    DHCPOptions5    = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #DHCP server

    package = OPCODE + HARDWARE_TYPE + HARDWARE_LEN + HOPS + TRANSACTION_ID + SECONDS_ELAPSED + FLAGS \
            + CLIENT_IP_ADDR + YOUR_IP_ADDR + SERVER_IP_ADDR + GATEWAY_IP_ADDR + CLIENT_HARD_AD1 \
            + CLIENT_HARD_AD2 + CLIENT_HARD_AD3 + CLIENT_HARD_AD4 + CLIENT_HARD_AD5 + Magiccookie \
            + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

    return package


def print_mac_address(mac):
    printable_mac = ""
    for i in range(5):
        printable_mac += str(f"{mac[i]:0{2}x}") + ":"
    printable_mac += str(f"{mac[5]:0{2}x}")
    # print(print_mac)
    return printable_mac


def print_ip_address(ip):
    printable_ip = str(data[16]) + "." + str(data[17]) + "." + str(data[18]) + "." + str(data[19])
    # print(print_ip)
    return printable_ip


def update_ip_status(ips):
    for key, value in ips.items():
        time_now = round(time.time() * 1000)
        if (value[1] != 'reserved'):
            if (int(value[1]) < time_now):
                new_value = ('free', 0)
                ip_status[key] = new_value
    # pprint.pprint(ip_status)


def is_mac_block(mac, black_list):
    for black_mac in black_list:
        same_flag = 1
        parts = black_mac.split(":")
        
        for i in range(6):
            # print("p", str(parts[i]))
            # print("h", f"{mac[i]:0{2}x}")
            if (parts[i] != f"{mac[i]:0{2}x}"):
                same_flag = 0
        
        if (same_flag):
            return True

    return False


def is_ip_reserved(mac, reservation_list):
    for reserved in reservation_list:
        same_flag = 1
        parts = reserved.split(":")
        
        for i in range(6):
            if (parts[i] != f"{mac[i]:0{2}x}"):
                same_flag = 0
        
        if (same_flag):
            return reservation_list[reserved]

    return "0"


def has_ip(mac, ip_status):
    for key, value in ip_status.items():
        pre_mac = value[0]
        same_flag = 0
        if pre_mac != "free":
            same_flag = 1
            parts = pre_mac.split(":")
            # print(pre_mac)
            for i in range(6):
                if (parts[i] != f"{mac[i]:0{2}x}"):
                    same_flag = 0
        
        if (same_flag):
            return key

    return "0"


def show_clients(ip_status):
    # print(ip_status)
    print("Show Clients Status")
    print ("MAC ADDRESS         |  ASSIGNED IP    |   EXPIRE TIME")
    for key, value in ip_status.items():
        if (value[0] != "free"):
            if (value[1] == "reserved"):
                print (value[0], "  |  ", key, "  |  ", "Reserved")
            else:
                time_now = round(time.time() * 1000)
                expire = round((value [1] - time_now) / 1000)
                print (value[0], "  |  ", key, "  |  ", time.strftime('%H Hours, %M Minutes, %S Seconds', time.gmtime(expire)))


print("Setting Configs...")

lease_time = 0
reservation_list = {}
black_list = []
ip_status = {}

# reading json file
with open("configs.json") as json_file:
    data = json.load(json_file)

    if (data["pool_mode"] == "range"):
        from_ip = data["range"]["from"]
        to_ip = data["range"]["to"]
    
        from_ip_parts = from_ip.split(".")
        to_ip_parts = to_ip.split(".")

        # add ips to ip status list
        for i in range(int(from_ip_parts[3]), int(to_ip_parts[3]) + 1):
            ip = from_ip_parts[0] + "." + from_ip_parts[1] + "." + from_ip_parts[2] + "." + str(i)
            ip_status[ip] = ("free","0")
        
        # pprint.pprint(ip_status)

    elif (data["pool_mode"] == "subnet"):
        ip_block = data["subnet"]["ip_block"]
        subnet_mask = data["subnet"]["subnet_mask"]

        from_ip_parts = ip_block.split(".")
        to = subnet_mask.split(".")[3]

        # add ips to ip status list
        for i in range(int(from_ip_parts[3]) + 1, int(to) + 1):
            ip = from_ip_parts[0] + "." + from_ip_parts[1] + "." + from_ip_parts[2] + "." + str(i)
            ip_status[ip] = ("free","0")

        # pprint.pprint(ip_status)

    lease_time = data["lease_time"]
    reservation_list = data["reservation_list"]
    for key, value in reservation_list.items():
        ip_status[value] = (key,"reserved")
    # print(reservation_list)
    # pprint.pprint(ip_status)
    
    black_list = data["black_list"]
    # print(black_list)

print("OK\n")



print("DHCP server is starting...\n")
    
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
s.bind(('', SERVER_PORT))
dest = ('255.255.255.255', CLIENT_PORT)

while 1:

    update_ip_status(ip_status)
    show_clients(ip_status)

    assigned_ip = ""

    try:
        print("Waiting for DHCP discovery...\n")
        data, address = s.recvfrom(MAX_BYTES)
        update_ip_status(ip_status)
        print("Receive DHCP discovery.")
        #print(data)

        mac_address = data[28:34]

        # check if not blocked
        if(is_mac_block(mac_address, black_list)):
            print("BLOCK MAC ADDRESS\n")
            continue
        else:
            print("Valid mac address\n")

        # check if reserved
        reserved_ip = is_ip_reserved(mac_address, reservation_list)
        if (reserved_ip != "0"):
            print("IP" , reserved_ip, "reserved before\n")
            print("Send DHCP offer with reserved ip.\n")
            data = offer_get(reserved_ip)
            assigned_ip = reserved_ip
            s.sendto(data, dest)

        else:
            # if has ip before, update lease time
            pre_ip = has_ip(mac_address, ip_status)
            if (pre_ip != "0"):
                print("This pc has ip before\n")
                free_time = round(time.time() * 1000) + (lease_time * 1000)
                new_value = (print_mac_address(mac_address), free_time)
                ip_status[key] = new_value
                data = offer_get(pre_ip)
                assigned_ip = pre_ip
                s.sendto(data, dest)

            else:
                sent = False
                for key, value in ip_status.items():
                    if (value[0] == "free"): 
                        print("New IP should assign")
                        # pprint.pprint(ip_status)
                        free_time = round(time.time() * 1000) + (lease_time * 1000)
                        new_value = (print_mac_address(mac_address), free_time)
                        ip_status[key] = new_value
                        # print(key, "assigend")
                        # pprint.pprint(ip_status)
                        # print_mac_address(mac_address)
                        data = offer_get(key)
                        assigned_ip = key
                        s.sendto(data, dest)
                        sent = True
                        print("Send DHCP offer.\n")
                        break    
                if (sent == False):
                    print("There is no empty IP")
                    continue

        while 1:
            try:
                print("Wait DHCP request.\n")
                data, address = s.recvfrom(MAX_BYTES)
                update_ip_status(ip_status)
                print("Receive DHCP request.\n")
                #print(data)

                print("Send DHCP ack.\n")
                data = pack_get(assigned_ip)
                s.sendto(data, dest)
                break
            except:
                raise
    except:
        raise
