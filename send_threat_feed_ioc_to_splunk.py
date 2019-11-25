#!/usr/bin/env python3
""" Script to parse IOC (Indicator Of Compromise) from Open Source Threat Feed websites """

import ipaddress
import requests
import json
#import iocextract

""" Splunk HTTP Event Collector URL and Token """
hec_endpoint = 'http://127.0.0.1:8088/services/collector'
hec_token = ''
headers = {"Authorization": 'Splunk ' + hec_token}
plist = []
list = []
file = 'feeds.json'

""" Extract IOCs from a website """
def parse_ioc_from_website(url):
	try:
		response = requests.get(url)
		#response.encoding = 'utf-8'
		data = response.text
		ip_list = data.splitlines()
		return ip_list
	except Exception:
                print(f"URL fetch error: {response.text}")
 	
""" Check IPv4 address or range Does not parse CIDR """
def validate_ipaddress(ip):
	try:
		range_of_ips = []
		if not ip.startswith('#'):
			""" Opted to not parse CIDR as the could be large """
			cidr_check = ip.split('/')
			if len(cidr_check) == 2:
				pass
			""" parse IP range e.g. 192.168.0.1-192.168.1.254 """
			parsed_ip = ip.split('-')
			if len(parsed_ip) == 2:
				start_ip = ipaddress.IPv4Address(parsed_ip[0])
				end_ip = ipaddress.IPv4Address(parsed_ip[1])
				for ip_int in range(int(start_ip), int(end_ip)):
					range_of_ips.append(str(ipaddress.ip_address(ipaddress.IPv4Address(ip_int))))
			""" parse a single address """
			elif len(parsed_ip) == 1:
				range_of_ips.append(str(ipaddress.ip_address(parsed_ip[0])))
			else:
				range_of_ips.append(str(ipaddress.ip_address(ip)))
			return range_of_ips
	except ValueError as errorCode:
       		print(errorCode)
       		return False
 
""" Send IOCs to Splunk """
def send_to_splunk(final_payload):
	try:
		r = requests.post(hec_endpoint, final_payload, headers=headers, verify=False)
		if (r.status_code != 200):
            		print('failed with non 200 status code')
            		print(r.text)
            		failed = True
		elif (r.status_code == 200):
            		print(r.status_code, r.text)
            		failed = False
	except Exception:
        	print(f"URL fetch error: {r.text}")

 
def main():
	try:
		""" testing local files """
		"""
                with open(file,"r") as fp:
                        list = [line.strip() for line in fp.readlines()]
                fp.close()
                """

		with open(file, 'r') as fn:
       			 feed_data=fn.read()

		threat_feeds = json.loads(feed_data)

		for threat_feed in threat_feeds['feeds']:
			tf = threat_feed['feed_name']
			tf_type = threat_feed['feed_type']
			tf_url = threat_feed['feed_url']
			list = parse_ioc_from_website(tf_url)

			if tf_type == 'ip':
				for ip in list:
					validated_ip = validate_ipaddress(ip)
					if validated_ip is not None:
						for ioc in validated_ip:
							""" build JSON payload to send to Splunk """
							payload = '{"sourcetype": "_json", "event": {"ip": "' + ioc + '","feed":"' + tf + '"}}'
							plist.append(payload)
				""" send single JSON payload to Splunk """
				final_payload = ''.join(plist)
				send_to_splunk(final_payload)
			""" parse using iocextract for these IOCs """
			elif tf_type == 'domain':
				pass
			elif tf_type == 'url':
				pass
			elif tf_type == 'hash':
				pass
			elif tf_type == 'email':
				pass
			else:
				print(f"Unknown or bad IOC type")
	except Exception:
                print(f"Something went wrong")

if __name__ == "__main__":
    main()
