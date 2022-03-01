from scapy.all import ARP, Ether, srp, socket
import scapy.all as scapy
import nmap
import socket

def get_mac_ip():
    doelwit = "192.168.1.1/24" #ip adress voor de bestemming
    arp = ARP(pdst=doelwit) #hier wordt een arp request aangemaakt
    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff") #broadcasting mac address om de mac adres te achterhalen
    packet = ethernet/arp
    resultaat = srp(packet, timeout=3, verbose=0)[0]

    apparaten = []

    for sent, received in resultaat: #hier wordt de mac en ip toegevoegd
        apparaten.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("Beschikbare apparaten op het netwerk:")
        print("IP" + " "*18+"MAC")
        for client in apparaten:
            print("{:16}    {}".format(client['ip'], client['mac']))
            w.write("\n" + "{:16}    {}".format(client['ip'], client['mac'])) #hier wordt het toegevoegd aan het bestand
            

def get_hostnaam():
    try:
        hostnaam = socket.gethostbyaddr(doelwit)
        print("Hostname :  ",hostnaam[0])
    except:
        print("Geen hostname gevonden")
        w.write("\Geen hostname gevonden!\n")
    


def get_poort():
    beginreeks = 60 #hier wordt gekeken welke poorten je kan selecteren
    eindereeks = 61
    scanner = nmap.PortScanner()
    try:
        for i in range(beginreeks,eindereeks+1):
#hier controleert hij de state van de poorten, daarna wordt hij in het bestand gezet.
            resultaat = scanner.scan(doelwit,str(i))
            resultaat = resultaat['scan'][doelwit]['tcp'][i]['state'] 
            print(f'port {i} is {resultaat}.')
            w.write("\n" + f'port {i} is {resultaat}.')
    except:
        print("Geen poorten gevonden!")
        w.write("\nGeen poorten gevonden! \n")

def get_operatingsysteem():
    #via nmap gaat hij zoeken naar de OS
    try:
        nmap = nmap.PortScanner() #hier gebruikt hij de functie van nmap "portscanner"
        machine = nmap.scan(doelwit, arguments='-O') #hier wordt het doelwit geselecteerd om te scannen
        print(machine['scan'][doelwit]['osmatch'][0]['osclass'][0]['osfamily'])
        w.write("\n")
        w.write("\n" + machine['scan'][doelwit]['osmatch'][0]['osclass'][0]['osfamily'] + "\n") #hier wordt het toegevoegd in het bestand.
    except:
        print("Geen os gevonden!")
        w.write("\Geen os gevonden! \n")



w = open("netwerkinfo.txt","a") #hier wordt het bestand netwerkinfo.txt geopend
get_mac_ip() 
doelwit = input("doelwit: ")
w.write("\n")
w.write("\nDoelwit is: " + doelwit + "\n")
get_hostnaam()
get_poort()
get_operatingsysteem()
w.write("\neinde van de scan!\n")
w.close() #hier wordt het bestand afgesloten en kan er geen informatie meer aan worden toegevoegd.
 
