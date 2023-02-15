import requests
import json
from socket import gethostbyname
from warnings import warn

class Coordinates:

class Parser:
    
class CorrelateIP:

    def __init__(self, target_url, ip=None, location_finder_url='https://ipapi.co/'):
        self.ip = ip
        self.location_finder_url = location_finder_url

        if "https://" in target_url:
            target_url = target_url[8:]
        elif "http://" in target_url:
            target_url = target_url[7:]

        self.target_url = target_url

        if ip == None:
            self.ip = self.get_ip()

    def get_ip(self):
        try:
            ip = gethostbyname(self.target_url)
        except:

        


    def get_location(self):
        ip = self.get_ip()
        response = requests.get(f"{self.location_finder_url}{ip}/json").json()
        location_data = {
            "ip" : ip,
            "city" : response.get("city"),
            "region" : response.get("region"),
            "country" : response.get("country_name"),
            "country code" : response.get("country_code"),
            "latitude" : response.get("latitude"),
            "longitude" : response.get("longitude")
        }

        return location_data

    

class Maps:
