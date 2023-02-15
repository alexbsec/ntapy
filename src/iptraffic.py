import requests
import json
import socket

class Coordinates:

class Parser:
    
class CorrelateIP:

    def __init__(self, target_url, ip=None, location_finder_url='https://ipapi.co/'):
        self.target_url
        self.ip = ip
        self.location_finder_url = location_finder_url

        if ip == None:
            self.ip = self.get_ip()

    def get_ip(self):
        


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
