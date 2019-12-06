#!/usr/bin/env python3

import warnings
import ipaddress
import requests
import iocextract
import json
import re

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
hec_endpoint = 'https://http-inputs-gds.splunkcloud.com/services/collector'
hec_token = ''

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
		stripped_cidr = [ioc_ip for ioc_ip in ip if '/' not in ioc_ip]
		""" we are not processing CIDR at the moment """
		for ip_to_parse in stripped_cidr:
			""" check for ip range non-CIDR """
			#print(ip_to_parse)
			if '-' in ip_to_parse:
				parsed_ip = ip_to_parse.split('-')
				if len(parsed_ip) == 2:
					start_ip = ipaddress.IPv4Address(parsed_ip[0])
					end_ip = ipaddress.IPv4Address(parsed_ip[1])
					for ip_int in range(int(start_ip), int(end_ip)):
						range_of_ips.append(str(ipaddress.ip_address(ipaddress.IPv4Address(ip_int))))
			else:
				""" parse single IP address """
				range_of_ips.append(str(ipaddress.ip_address(ip_to_parse)))
		#print(range_of_ips)
		return range_of_ips
	except ValueError as errorCode:
		print(errorCode)
		return False

def parse_alienvault_reputation_data(indicators):
	av_ioc_list = []
	for otx_ip in indicators:
		#print(otx_ip)
		av_ioc = otx_ip.split('#')
		av_ioc_list.append(av_ioc[0])
	#print(av_ioc_list)
	parsed_av_list = validate_ipaddress(av_ioc_list)
	return parsed_av_list

""" build IOC payload for Splunk """
def build_payload(ioc, tf, tf_type):
	payload = '{"sourcetype": "_json", "event": {"feed": "' + tf + '","indicator_type": "' + tf_type + '","indicator":"' + ioc + '"}}'
	indicator_list.append(payload)
	return indicator_list

""" send IOC payload to Splunk """
def send_to_splunk(final_payload, tf):
	try:
		r = requests.post(hec_endpoint, final_payload, headers=headers, verify=False, allow_redirects=True)
		if (r.status_code != 200):
			print(f"feed for {tf_name} failed with non 200 status code")
			#print('failed with non 200 status code')
			print(r.text)
			failed = True
		elif (r.status_code == 200):
			print(f"{tf} returned ", r.status_code, r.text)
			#print(r.status_code, r.text)
			failed = False
	except Exception:
			print(f"URL fetch error: {r.text}")


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
			i_list = [i for i in list if '#' not in i]

			if tf == 'AlienVault OTX Reputation data':
				print('Parsing AV')
				parsed_alienvault_iocs = parse_alienvault_reputation_data(list)
				for av_indicator in parsed_alienvault_iocs:
					build_payload(av_indicator,tf,tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload, tf)
			elif tf_type == 'ip':
				validated_ip_list = validate_ipaddress(i_list)
				for parsed_ioc_ip in validated_ip_list:
					build_payload(parsed_ioc_ip,tf,tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload, tf)
			elif tf_type == 'domain':
				for domain_name in i_list:
					extracted_domain = re.match(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}',domain_name)
					build_payload(extracted_domain.group(0),tf,tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload, tf)
			elif tf_type == 'url':
				for url in i_list:
					build_payload(url, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload, tf)
			elif tf_type == 'hash':
				for hash in i_list:
					if not hash or hash.startswith('#'):
						pass
					else:
						build_payload(hash, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload, tf)
			elif tf_type == 'email':
				for email in i_list:
					if not email or email.startswith('#'):
						pass
					else:
						build_payload(email, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload, tf)
			elif tf_type == 'ipv6':
				for ipv6 in i_list:
					if not ipv6 or ipv6.startswith('#'):
						pass
					else:
						build_payload(ipv6, tf, tf_type)
				final_payload = ''.join(indicator_list)
				send_to_splunk(final_payload, tf)
			else:
				print(f"Unknown or bad IOC type")
	except Exception:
		print(f"Something went wrong - check feeds file is valid JSON")

if __name__ == "__main__":
	main()
