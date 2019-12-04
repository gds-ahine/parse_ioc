#!/usr/bin/env python3

import ipaddress
import requests
import iocextract
import json
import re

hec_endpoint = 'http://127.0.0.1:8088/services/collector'
hec_token = 'aabc8410-f63e-4ba7-9d68-a166d4a0e699'

headers = {"Authorization": 'Splunk ' + hec_token}
indicator_list = []
list = []
file = 'feeds.json'

def parse_ioc_from_website(url):
	try:
		response = requests.get(url)
		data = response.text
		ioc_list = data.splitlines()
		return ioc_list
	except Exception:
		print(f"URL fetch error: {response.text}")

"""
custom IP validation as iocextract.extract_ips or ipv4s cannot deal
with ip ranges e.g. 192.168.0.1-192.168.0.253
"""
def validate_ipaddress(ip):
	try:
		range_of_ips = []
		if not ip or ip.startswith('#'):
			pass
		else:
			""" do not process CIDR for now """
			cidr_check = ip.split('/')
			if len(cidr_check) == 2:
				pass
			""" get begin and end IP for a range """
			parsed_ip = ip.split('-')
			if len(parsed_ip) == 2:
				start_ip = ipaddress.IPv4Address(parsed_ip[0])
				end_ip = ipaddress.IPv4Address(parsed_ip[1])
				for ip_int in range(int(start_ip), int(end_ip)):
					range_of_ips.append(str(ipaddress.ip_address(ipaddress.IPv4Address(ip_int))))
					""" parse single IP address """
			elif len(parsed_ip) == 1:
				range_of_ips.append(str(ipaddress.ip_address(parsed_ip[0])))
			else:
				range_of_ips.append(str(ipaddress.ip_address(ip)))
			return range_of_ips
	except ValueError as errorCode:
		print(errorCode)
		return False


""" build IOC payload for Splunk """
def build_payload(ioc, tf, tf_type):
	payload = '{"sourcetype": "_json", "event": {"feed": "' + tf + '","indicator_type": "' + tf_type + '","indicator":"' + ioc + '"}}'
	indicator_list.append(payload)
	return indicator_list

""" send IOC payload to Splunk """
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

""" use iocextract for urls, email, hash and ipv6 feeds """
def extract_ioc(ioc, tf, tf_type):
	if tf_type == 'url':
		for parsed_url in iocextract.extract_urls(ioc, refang=True):
			if not ioc or ioc.startswith('#'):
				pass
			else:
				build_payload(parsed_url, tf, tf_type)
		final_payload = ''.join(indicator_list)
		send_to_splunk(final_payload)
		return final_payload


def main():
	try:
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
							build_payload(ip,tf,tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload)
			elif tf_type == 'domain':
				for domain_name in list:
					if not domain_name or domain_name.startswith('#'):
						pass
					else:
						extracted_domain = re.match(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}',domain_name)
						build_payload(extracted_domain.group(0),tf,tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload)
			elif tf_type == 'url':
				for url in list:
					if not url or url.startswith('#'):
						pass
					else:
						build_payload(url, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload)
			elif tf_type == 'hash':
				for hash in list:
					if not hash or hash.startswith('#'):
						pass
					else:
						build_payload(hash, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload)
			elif tf_type == 'email':
				for email in list:
					if not email or email.startswith('#'):
						pass
					else:
						build_payload(email, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload)
			elif tf_type == 'ipv6':
				for ipv6 in list:
					if not ipv6 or ipv6.startswith('#'):
						pass
					else:
						build_payload(ipv6, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload)
			else:
				print(f"Unknown or bad IOC type")
	except Exception:
		print(f"Something went wrong - check feeds file is valid JSON")

if __name__ == "__main__":
	main()