
import socket, sys
import struct
import threading
import uuid
import time
import queue
from multiprocessing.pool import ThreadPool

ETH_P_ALL = 0x0003

sip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sip.connect(("8.8.8.8", 80))
myip=sip.getsockname()[0]
sip.close()
que = queue.Queue()
def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)
print (str(hex(uuid.getnode())).encode) 

nw,mask=sys.argv[1].split('/')

def arpmonitor():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')
    npacotes=0
    npacotesip=0
    npacotesarp=0
    npacotesicmp=0
    npacotestcp=0
    npacotesudp=0
    smallpct=100000
    bigpct=0
    #s.bind(('enp4s0',0))
    #s.bind(('enp3s0',0))
    s.bind(('eno1',0))

    start_time = time.time()
    lsend=[]
    ldest=[]
    start_time = time.time()
    while(time.time()-start_time<5.0):
        (packet,addr) = s.recvfrom(65536)
        if(len(packet)>bigpct):
            bigpct=len(packet)
        if(len(packet)<smallpct):
            smallpct=len(packet)
        npacotes=npacotes+1

        eth_length = 14
        eth_header = packet[:14]

        eth = struct.unpack("!6s6sH",eth_header)

        print("MAC Dst: "+bytes_to_mac(eth[0]))
        print("MAC Src: "+bytes_to_mac(eth[1]))
        print("Type: "+hex(eth[2]))
    

        if eth[2] == 0x0806 :
            print("ARP Packet")
            npacotesarp=npacotesarp+1
            arp_header = packet[eth_length:28+eth_length]
            arph = struct.unpack("!HHBBHIH4sHI4s",arp_header)
            print("len de arph "+str(len(arph)))
            if(arph[4]==1):
                print("request")
            else:
                print("reply")
            s_addr = socket.inet_ntoa(arph[7])
            d_addr = socket.inet_ntoa(arph[10])
            present=0
            for a in lsend:
                if(a[0]==s_addr):
                    a[1]=a[1]+1
                    present=1
            if present==0:
                lsend.append(list((s_addr,1)))
            present=0
            for a in ldest:
                if(a[0]==d_addr):
                    a[1]=a[1]+1
                    present=1
            if present==0:
                ldest.append(list((d_addr,1)))
            print("IP Src: "+s_addr)
            print("IP Dst: "+d_addr)
        print("")
    
    return (lsend,ldest)
        
    
    

if(nw[0:-1]==myip[0:len(nw)-1]):#so aceitamos redes terminando em 0
    print("mesma rede")
    
    t1=threading.Thread(target=lambda q: q.put(arpmonitor()), args=(que,))
    t1.start()
    time.sleep(1)


    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')
    #s.bind(('enp4s0',0))
    s.bind(('eno1',0))
    
    # Header Ethernet
    # MAC Destino - 6 bytes
    dest_mac = b"\xff\xff\xff\xff\xff\xff"
    # MAC Origem - 6 bytes
    source_mac = b"\xa4\x1f\x72\xf5\x90\x41"
    #source_mac= str(hex(uuid.getnode())).encode
    protocol = 0x0806

    eth_hdr = struct.pack("!6s6sH", dest_mac, source_mac, protocol)

    # Header ARP
    htype = 1
    ptype = 0x0800
    hlen = 6
    plen = 4
    op = 1 # request
    src_ip = socket.inet_aton(myip)
    target_mac = b"\x00\x00\x00\x00\x00\x00"
    
    for i in range(1,255):

    
        target_ip = socket.inet_aton(nw[0:-1]+str(i))

        arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, op, source_mac, src_ip, target_mac, target_ip)

        packet = eth_hdr+arp_hdr

        s.send(packet)
    t1.join()
    senders,targets=que.get()

    for a in senders:
        print(a)
        if(a!=myip and nw[0:-1]==a[0:len(nw)-1]):
            print(a)


    
else:#Redes diferentes
    print("Rede Externa")
