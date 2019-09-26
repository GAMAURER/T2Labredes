import socket, sys
import struct

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        a = msg[i]
        b = msg[i+1]
        s = s + (a+(b << 8))
    s = s + (s >> 16)
    s = ~s + 0xffff
    return socket.ntohs(s)
for i in range(1,100):
        
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("tcp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')

    # Include IP header
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Header IP
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton("192.168.100.160")
    ip_daddr = socket.inet_aton("192.168.100.146")

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)


    # ICMP Echo Request Header
    sourceport = 5498
    destinationport= i
    sequencenumber= 0
    ackn=0
    hlr=0b01010000
    flags=2 
    windowsize=30
    mychecksum = 0
    urg=0
    icmp_packet = struct.pack("!HHLLBBHHH", sourceport, destinationport, sequencenumber, ackn, hlr, flags,windowsize,mychecksum,urg)
    mychecksum=checksum(icmp_packet)
    icmp_packet = struct.pack("!HHLLBBHHH", sourceport, destinationport, sequencenumber, ackn, hlr, flags,windowsize,mychecksum,urg)
    #mychecksum=checksum(icmp_packet)
    # mychecksum = checksum(icmp_packet)

    # print("Checksum: {.02x}".format(mychecksum))

    # icmp_packet = struct.pack("!BBHHH14s", type, code, mychecksum, identifier, seqnumber, payload)

    dest_ip = "192.168.100.146"
    dest_addr = socket.gethostbyname(dest_ip)

    s.sendto(ip_header+icmp_packet, (dest_addr,0))