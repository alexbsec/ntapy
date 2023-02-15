import requests
import pyshark  
import socket
import os
import time
import geoip2.database




class IPGeoLocator:

    def __init__(self, target_url=None, ip= None, port=443, timeout=60, verbose=True):
        self.geo_path_country = "./GeoLite2-Country_20230214/GeoLite2-Country.mmdb"
        self.geo_path_city = "./GeoLite2-City_20230214/GeoLite2-City.mmdb"
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.verbose = verbose

        if target_url == None and ip == None:
            print(f"[!] No target/ip was provided.")
            exit(1)

        if target_url != None:
            if "https://" in target_url:
                target_url = target_url[8:]
            elif "http://" in target_url:
                target_url = target_url[7:]
                self.port = 80

        self.target_url = target_url

        if ip == None:
            self.ip = self.get_ip()

    def get_ip(self):
        try:
            addr_info = socket.getaddrinfo(self.target_url, port=self.port)
            for info in addr_info:
                (family, socket_type, proto, canonname, socket_addr) = info
                if family == socket.AF_INET and socket_type == socket.SOCK_STREAM:
                    ip = socket_addr[0]
                    self.proto = proto
                    self.canon_name = canonname
                    #add error exception here as well
        except socket.gaierror:
            print(f"[!] Unknown hostname {self.target_url}")
            raise

        return ip

    def get_location(self):
        ip = self.ip
        with geoip2.database.Reader(self.geo_path_country) as country_reader:
            with geoip2.database.Reader(self.geo_path_city) as city_reader:
                response_country = country_reader.country(ip)
                response_city = city_reader.city(ip)
                location_data = {
                    "IP" : ip,
                    "Country" : response_country.country.iso_code,
                    "City" : response_city.city.name,
                    "Latitude" : response_city.location.latitude,
                    "Longitude" : response_city.location.longitude
                }

        return location_data

    def fetch(self):
        if self.port != None and self.verbose:
            print(f"[-] Fetching geo location for {self.ip}:{self.port}.")
        elif self.verbose:
            print(f"[-] Fetching geo location for {self.ip}.")
        location_data = self.get_location()
    
        if self.verbose:
            print('[+] Fetching successful.\n')
            print('[*] Data retrieved:')

        for key in location_data:
            if self.verbose:
                print(f"[+] {key}: {location_data[key]}")
            setattr(self, key.lower(), location_data[key])

        if self.verbose:
            print("")
        

class PacketParser:

    def __init__(self, target_url=None, port=443, interface='wlan0', timeout=60):
        self.target_url = target_url
        self.interface = interface
        self.timeout = timeout
        self.port = port
        self.ip_location = IPGeoLocator(target_url, port=port, timeout=timeout)
        pcap_path = self.make_pcap_path()
        print(f"[-] Starting packet capture.\n")
        self.pcap_size = self.print_pcap(pcap_path)


    def print_pcap(self, pcap_path):
        shot = pyshark.LiveCapture(
            interface=self.interface,
            output_file=pcap_path,
        )
        start = time.time()
        pcap_size = 0
        for i, packet in enumerate(shot.sniff_continuously()):
            if os.path.getsize(pcap_path) != pcap_size:
                pcap_size = os.path.getsize(pcap_path)
            if not isinstance(packet, pyshark.packet.packet.Packet):
                continue
            try:
                src = packet.ip.src
                dst = packet.ip.dst
                src_country, dst_country = "", ""
                print(f"[+] Source: {src} ------------------> Dest: {dst}")
                try:
                    src_ip_geo = self.ret_geo(src)
                    src_country = src_ip_geo.country
                except:
                    src_country = "UNKNOWN"
                    pass
                try:
                    dst_ip_geo = self.ret_geo(dst)
                    dst_country = dst_ip_geo.country
                except:
                    dst_country = "UNKNOWN"
                    pass


                print(f"[+] Source: {src_country} ------------------> Dest: {dst_country}\n")


            except AttributeError:
                pass
            if self.timeout and time.time() - start > self.timeout:
                break
                

        shot.clear()
        shot.close()

        return pcap_size

    
    def ret_geo(self, ip):
        ip_loc = IPGeoLocator(ip=ip, port=None, verbose=False)
        ip_loc.fetch()
        return ip_loc


    def make_pcap_path(self):
        pcap_dir ='./pcap/'
        if not os.path.exists(pcap_dir):
            os.makedirs(pcap_dir)
        pcap_path = os.path.join(pcap_dir, f'{self.target_url}-capture.cap')
        return pcap_path
        
       
def main():
    tgt = input("Input target url: ")
    ip_location = IPGeoLocator(tgt)
    ip_location.fetch()

    PacketParser(tgt)

if __name__ == '__main__':
    main()

            
            




#class Maps:
