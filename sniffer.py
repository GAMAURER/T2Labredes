
import socket, sys
import struct
import time

ETH_P_ALL = 0x0003
interface=sys.argv[1]
def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

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
totaltraffic=0
#s.bind(('enp4s0',0))
#s.bind(('enp3s0',0))
s.bind((interface,0))
try:    
    start_time = time.time()
    lsend=[]
    ldest=[]
    
    while(True):
        (packet,addr) = s.recvfrom(65536)
        totaltraffic= totaltraffic + len(packet)
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
       
        if eth[2] == 0x0800 :
            print("IP Packet")
            npacotesip=npacotesip+1
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
            print("IP Src: "+s_addr)
            present=0
            for a in lsend:
                if(a[0]==s_addr):
                    a[1]=a[1]+1
                    present=1
            if present==0:
                
                lsend.append(list((s_addr,1)))
            
            print("IP Dst: "+d_addr)
            present=0
            for a in ldest:
                if(a[0]==d_addr):
                    a[1]=a[1]+1
                    present=1
            if present==0:
                ldest.append(list((d_addr,1)))
            if(protocol==17):#UDP
                print("UDP")
                npacotesudp=npacotesudp+1
                udp_header = packet[20+eth_length:20+eth_length+8]
                udph= struct.unpack("!HHHH",udp_header)
                sourcep=udph[0]
                print("Source "+str(udph[0]))
                print("Dest "+str(udph[1]))
                destp=udph[1]
            elif(protocol==6):#TCP
                print("TCP")
                npacotestcp=npacotestcp+1
                tcp_header = packet[20+eth_length:20+eth_length+4]
                tcph= struct.unpack("!HH",tcp_header)
                print("Source "+str(tcph[0]))
                print("Dest "+str(tcph[1]))

            elif(protocol==1):
                print("ICMP")
                npacotesicmp=npacotesicmp+1
                icmp_header = packet[20+eth_length:20+eth_length+8]
                icmph= struct.unpack("!BBHHH",icmp_header)
                icmpt=icmph[0]
                print("ICMP Type = "+str(icmpt))
                icmpcode=icmph[1]
                print("ICMP Code = "+str(icmpcode))
                if(icmpt==0):#echoreply
                    print("Echo Reply")
                    er_header = packet[28+eth_length:28+eth_length+8]
                    erh= struct.unpack("!HH4s",er_header)
                    print("Identifier "+ str(erh[0]))
                    print("Sequence Number "+ str(erh[1]))
                    print("Payload " +str(erh[2]))#arrumar

                elif(icmpt==8):#echorequest
                    print("Echo Request")
                    er_header = packet[28+eth_length:28+eth_length+8]
                    erh= struct.unpack("!HHBBBB",er_header)
                    print("Identifier "+ str(erh[0]))
                    print("Sequence Number "+ str(erh[1]))
                elif(icmpt==3):#destureach
                    print("Destination unreachable")
                elif(icmpt==11):#timeexceeded
                    print("Time Exceeded")

        if eth[2] == 0x0806 :
            print("ARP Packet")
            npacotesarp=npacotesarp+1
            arp_header = packet[eth_length:28+eth_length]
            arph = struct.unpack("!HHBBH6s4s6s4s",arp_header)
            print("len de arph "+str(len(arph)))
            if(arph[4]==1):
                print("request")
            else:
                print("reply")
            
            s_mac=bytes_to_mac(arph[5])
            print("MAC src: "+str(s_mac))
            
            d_mac=bytes_to_mac(arph[7])
            print("MAC dst: "+str(d_mac))
            s_addr = socket.inet_ntoa(arph[6])
            d_addr = socket.inet_ntoa(arph[8])
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
except KeyboardInterrupt:
        print("")
        print("Finalizando")
        
        print("Numero de pacotes monitorados "+str(npacotes))
        print("Total de bytes recebidos: "+str(totaltraffic))
        print("Porcentagem de pacotes IP "+str(100*(npacotesip/npacotes)))
        print("Porcentagem de pacotes ARP "+str(100*(npacotesarp/npacotes)))
        print("Porcentagem de pacotes TCP "+str(100*(npacotestcp/npacotes)))
        print("Porcentagem de pacotes UDP "+str(100*(npacotesudp/npacotes)))
        print("Porcentagem de pacotes ICMP "+str(100*(npacotesicmp/npacotes)))
        print("Menor pacote foi de "+str(smallpct)+" bytes")
        print("Maior pacote foi de "+str(bigpct)+" bytes")
        
        lsend.sort(key=lambda tup: tup[1])
        ldest.sort(key=lambda tup: tup[1])
        print("IPs que mais enviaram "+str(lsend[-5:]))
        print("IPs que mais receberam "+str(ldest[-5:]))
        

        print("Tempo total de monitoramento "+str(time.time() - start_time))

