
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
mymac=str(hex(uuid.getnode())).encode 
myip=sip.getsockname()[0]
sip.close()
que = queue.Queue()
def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        a = msg[i]
        b = msg[i+1]
        s = s + (a+(b << 8))
    s = s + (s >> 16)
    s = ~s + 0xffff
    return socket.ntohs(s)



nw,mask=sys.argv[1].split('/')
smallport=sys.argv[2]
bigport=sys.argv[3]
interface=sys.argv[4]

def tcpmonitor():

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')

    #s.bind(('enp4s0',0))
    #s.bind(('enp3s0',0))
    s.bind((interface,0))

    start_time = time.time()
    lsend=[]
    ldest=[]
    
    while(time.time()-start_time<300.0):
        (packet,addr) = s.recvfrom(65536)


        eth_length = 14
        eth_header = packet[:14]

        eth = struct.unpack("!6s6sH",eth_header)

    
        if eth[2] == 0x0800 :
            
            
            ip_header = packet[eth_length:20+eth_length]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl*4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            

                
  

            if(protocol==6):#TCP
                #print("TCP")
                
                
                tcp_header = packet[20+eth_length:20+eth_length+4]
                tcph= struct.unpack("!HH",tcp_header)
                #print(s_addr[0:len(nw)])
                #print(nw[:-1])
                if(s_addr[0:len(nw)-1]==nw[:-1]):
                #if(True):
                    print("Porta "+str(tcph[0])+" do IP "+str(s_addr)+" Está aberta")
    return
                    


def arpmonitor():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    #print('Socket created!')

    #s.bind(('enp4s0',0))
    #s.bind(('enp3s0',0))
    s.bind((interface,0))

    start_time = time.time()
    lsend=[]
    ldest=[]
    start_time = time.time()
    while(time.time()-start_time<5.0):
        (packet,addr) = s.recvfrom(65536)

        eth_length = 14
        eth_header = packet[:14]

        eth = struct.unpack("!6s6sH",eth_header)

        #print("MAC Dst: "+bytes_to_mac(eth[0]))
        #print("MAC Src: "+bytes_to_mac(eth[1]))
        #print("Type: "+hex(eth[2]))
    

        if eth[2] == 0x0806 :
            #print("ARP Packet")
            #npacotesarp=npacotesarp+1
            arp_header = packet[eth_length:28+eth_length]
            arph = struct.unpack("!HHBBHIH4sHI4s",arp_header)
            #print("len de arph "+str(len(arph)))
            #if(arph[4]==1):
            #    print("request")
            #else:
            #    print("reply")
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
            #print("IP Src: "+s_addr)
            #print("IP Dst: "+d_addr)
        #print("")
    
    return (lsend,ldest)


#create a raw socket
def tcpsender(ips):
    
    def checksumtcp(msg):
        s = 0
    # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i+1] )
            s = s + w

            s = (s>>16) + (s & 0xffff)
            #s = s + (s >> 16);
            #complement and mask to 4 byte short
            s = ~s & 0xffff

        return s
    t1=threading.Thread(target=lambda q: q.put(tcpmonitor()), args=(que,))
    t1.start()
    time.sleep(1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    for ipdest in ips: 
        for j in range(int(smallport),int(bigport)):
            
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            packet = ''

            source_ip = myip
            dest_ip = ipdest[0] 

           
            ihl = 5
            version = 4
            tos = 0
            tot_len = 20
            id = 54321  
            frag_off = 0
            ttl = 255
            protocol = socket.IPPROTO_TCP
            check = 10  
            saddr = socket.inet_aton ( source_ip )  
            daddr = socket.inet_aton ( dest_ip )

            ihl_version = (version << 4) + ihl

           
            ip_header = struct.pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)


            
            source = 12345  
            dest = j  
            seq = 0
            ack_seq = 0
            doff = 5    
            
            fin = 0
            syn = 1
            rst = 0
            psh = 0
            ack = 0
            urg = 0
            window = socket.htons (5840)

            
            check = 0
            urg_ptr = 0

            offset_res = (doff << 4) + 0
            tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

            
            tcp_header = struct.pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)

           
            source_address = socket.inet_aton( source_ip )
            dest_address = socket.inet_aton(dest_ip)
            placeholder = 0
            protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header)

            psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)
            psh = psh + tcp_header

            tcp_checksum = checksumtcp(psh)

            
            tcp_header = struct.pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)

            
            packet = ip_header + tcp_header

            s.sendto(packet, (dest_ip , 0 ))    
    return


def icmpmonitor():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    #print('Socket created!')

    s.bind((interface,0))

    start_time = time.time()
    lsend=[]
    ldest=[]
    start_time = time.time()
    while(time.time()-start_time<5.0):
        (packet,addr) = s.recvfrom(65536)

        

        eth_length = 14
        eth_header = packet[:14]

        eth = struct.unpack("!6s6sH",eth_header)

        #print("MAC Dst: "+bytes_to_mac(eth[0]))
        #print("MAC Src: "+bytes_to_mac(eth[1]))
        #print("Type: "+hex(eth[2]))
    

        if eth[2] == 0x0800 :
            ip_header = packet[eth_length:20+eth_length]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl*4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            



            if(protocol==1):
                #print("ICMP")
                
                icmp_header = packet[20+eth_length:20+eth_length+8]
                icmph= struct.unpack("!BBHHH",icmp_header)
                icmpt=icmph[0]
                #print("ICMP Type = "+str(icmpt))
                icmpcode=icmph[1]
                #print("ICMP Code = "+str(icmpcode))
                if(icmpt==0):#echoreply
                    #print("Echo Reply")
                    er_header = packet[28+eth_length:28+eth_length+8]
                    erh= struct.unpack("!HHBBBB",er_header)
                    #print("Identifier "+ str(erh[0]))
                    #print("Sequence Number "+ str(erh[1]))
                    #print("Payload " +str(chr(erh[2]))+str(chr(erh[3]))+str(chr(erh[4]))+str(chr(erh[5])))#arrumar
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

    
    return (lsend,ldest) 
    

if(nw[0:-1]==myip[0:len(nw)-1]):#so aceitamos redes terminando em 0
    print("Rede Local")
    
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
    s.bind((interface,0))
    
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
        if(a[0][0:len(nw)-1]==nw[:-1]):
            print("O IP "+str(a[0])+" está ativo")
    print("Existem "+str(len(senders))+" maquinas ativas nesta rede")
    tcpsender(senders)
else:#rede externa
    print("Rede externa")
    t1=threading.Thread(target=lambda q: q.put(icmpmonitor()), args=(que,))
    t1.start()
    time.sleep(1)



    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')

    # Include IP header
    for i in range(1,255):
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Header IP
        
        ip_ver = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = 0
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_ICMP
        ip_check = 0
        ip_saddr = socket.inet_aton(myip)
        ip_daddr = socket.inet_aton(nw[0:-1]+str(i))

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
            ip_proto, ip_check, ip_saddr, ip_daddr)


        # ICMP Echo Request Header
        type = 8
        code = 0
        mychecksum = 0xc233
        identifier = 12345
        seqnumber = 0
        payload = b"istoehumteste"

        icmp_packet = struct.pack("!BBHHH13s", type, code, mychecksum, identifier, seqnumber, payload)

        # mychecksum = checksum(icmp_packet)

        # print("Checksum: {.02x}".format(mychecksum))

        # icmp_packet = struct.pack("!BBHHH14s", type, code, mychecksum, identifier, seqnumber, payload)

        dest_ip = nw[0:-1]+str(i)
        dest_addr = socket.gethostbyname(dest_ip)

        s.sendto(ip_header+icmp_packet, (dest_addr,0))
    t1.join()
    senders,targets=que.get()
    
    for a in senders:
        if(a[0][0:len(nw)-1]==nw[:-1]):
        
            print("O IP "+str(a[0])+" está ativo")
    print("Existem "+str(len(senders))+" maquinas ativas nesta rede")
    tcpsender(senders)




# checksum functions needed for tcp checksum , found it in internet
