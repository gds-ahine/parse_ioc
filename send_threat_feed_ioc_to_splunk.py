import warnings
import ipaddress
import json
import re
import requests
import logging
import boto3

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
hec_endpoint = 'http://127.0.0.1:8088/services/collector'
splunk_hec_token = 'aabc8410-f63e-4ba7-9d68-a166d4a0e699'
indicator_list = []
list = []
urlhaus_list = []
file = 'feeds.json'
s3_bucket = 'ah-open-source-threat-feeds-test-bucket'
s3_ip_filename = 'ip.txt'
s3_domain_filename = 'domain.txt'
s3_url_filename = 'url.txt'
event = ''
context = ''


def update_s3_indicators_file(tf_type, i_list):
    tmp_ip_list = []
    tmp_domain_list = []
    tmp_url_list = []
    s3 = boto3.resource('s3')
    try:
        """ Check to see if we have previously ingested this IP """
        if tf_type == 'ip':
            s3.meta.client.download_file(s3_bucket, s3_ip_filename, '/tmp/' + s3_ip_filename)

            """ Download previously ingested IP file from S3 """
            with open('/tmp/' + s3_ip_filename, 'r+') as ipfile_ro:
                for ip_line in ipfile_ro:
                    previous_ip = ip_line.strip('\n')
                    tmp_ip_list.append(previous_ip)
            ipfile_ro.close()

            """ Get a list of IPs not already ingested """
            updated_ip_list = [ip_item for ip_item in i_list if ip_item not in tmp_ip_list]

            """ Update the S3 IP file """
            with open('/tmp/' + s3_ip_filename, 'a+') as ipfile_append:
                for new_ip in updated_ip_list:
                    ipfile_append.write(new_ip + '\n')
            ipfile_append.close()

            """ Upload the updated IP file to S3 """
            s3.meta.client.upload_file('/tmp/' + s3_ip_filename, s3_bucket, s3_ip_filename)

            """ Validate new IPs """
            validated_ip_addresses = validate_ipaddress(updated_ip_list)
            return validated_ip_addresses

        elif tf_type == 'domain':
            s3.meta.client.download_file(s3_bucket, s3_domain_filename, '/tmp/' + s3_domain_filename)

            """ Download previously ingested domain file from S3 """
            with open('/tmp/' + s3_domain_filename, 'r+') as domainfile_ro:
                for domain_line in domainfile_ro:
                    previous_domain = domain_line.strip('\n')
                    tmp_domain_list.append(previous_domain)
            domainfile_ro.close()

            """ Get a list of domains not already ingested """
            updated_domain_list = [domain_item for domain_item in i_list if domain_item not in tmp_domain_list]

            """ Update the S3 domain file """
            with open('/tmp/' + s3_domain_filename, 'a+') as domainfile_append:
                for new_domain in updated_domain_list:
                    domainfile_append.write(new_domain + '\n')
            domainfile_append.close()

            """ Upload the updated domain file to S3 """
            s3.meta.client.upload_file('/tmp/' + s3_domain_filename, s3_bucket, s3_domain_filename)

            return updated_domain_list

        elif tf_type == 'url':
            s3.meta.client.download_file(s3_bucket, s3_url_filename, '/tmp/' + s3_url_filename)

            """ Download previously ingested URL file from S3 """
            with open('/tmp/' + s3_url_filename, 'r+') as urlfile_ro:
                for url_line in urlfile_ro:
                    #print(url_line)
                    previous_url = url_line.strip('\n')
                    tmp_url_list.append(previous_url)
            urlfile_ro.close()

            #print(tmp_url_list)

            """ Get a list of URLs not already ingested """
            updated_url_list = [url_item for url_item in i_list if url_item not in tmp_url_list]

            #print(updated_url_list)

            """ Update the S3 URL file """
            with open('/tmp/' + s3_url_filename, 'a+') as urlfile_append:
                for new_url in updated_url_list:
                    urlfile_append.write(new_url + '\n')
            urlfile_append.close()

            """ Upload the updated URL file to S3 """
            s3.meta.client.upload_file('/tmp/' + s3_url_filename, s3_bucket, s3_url_filename)

            return updated_url_list
        else:
            pass
    except:
        print(f"Unable to update indicators file stored in S3")


def parse_ioc_from_website(url):
    try:
        response = requests.get(url)
        data = response.text
        ioc_list = data.splitlines()
        return ioc_list
    except Exception:
        print(f"URL fetch error: {response.text}")

def validate_ipaddress(ip):
    try:
        range_of_ips = []
        stripped_cidr = [ioc_ip for ioc_ip in ip if '/' not in ioc_ip]
        """ we are not processing CIDR at the moment """
        for ip_to_parse in stripped_cidr:
            """ check for ip range non-CIDR """
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
        return range_of_ips
    except ValueError as errorCode:
        print(errorCode)
        return False


def parse_alienvault_reputation_data(indicators):
    av_ioc_list = []
    for otx_ip in indicators:
        av_ioc = otx_ip.split('#')
        av_ioc_list.append(av_ioc[0])
    parsed_av_list = validate_ipaddress(av_ioc_list)
    return parsed_av_list


""" build IOC payload for Splunk """
def build_payload(ioc, tf, tf_type):
    payload = '{"sourcetype": "_json", "event": {"feed": "' + tf + '","indicator_type": "' + tf_type + '","indicator":"' + ioc + '"}}'
    indicator_list.append(payload)
    return indicator_list


""" build URLHaus payload for Splunk """
def build_urlhaus_payload(tf, tf_type, dateadded, url, url_status, threat, tags, urlhaus_url):
    payload = '{"sourcetype": "_json", "event": {"feed": "' + tf + '","indicator_type": "' + tf_type + '","indicator": ' + url + ',"status": ' + url_status + ',"threat": ' + threat + ',"tags": ' + tags + ',"date_added": ' + dateadded + ',"urlhaus_url": ' + urlhaus_url + '}}'
    indicator_list.append(payload)
    return indicator_list


""" send IOC payload to Splunk """
def send_to_splunk(final_payload, tf, splunk_hec_token):
    try:
        headers = {"Authorization": 'Splunk ' + splunk_hec_token}
        r = requests.post(hec_endpoint, final_payload, headers=headers, verify=False, allow_redirects=True)
        if (r.status_code != 200):
            print(f"feed for {tf} failed with non 200 status code")
            print(r.text)
            failed = True
        elif (r.status_code == 200):
            print(f"{tf} returned ", r.status_code, r.text)
            failed = False
    except Exception:
        print(f"URL fetch error: {r.text}")


def lambda_handler(event, context):
    try:
        #splunk_hec_token = get_ssm_parameter(ssm_param)
        with open(file, 'r') as fn:
            feed_data = fn.read()

        threat_feeds = json.loads(feed_data)

        for threat_feed in threat_feeds['feeds']:
            tf = threat_feed['feed_name']
            tf_type = threat_feed['feed_type']
            tf_url = threat_feed['feed_url']
            list = parse_ioc_from_website(tf_url)
            i_list = [i for i in list if '#' not in i]

            if tf == 'URLHaus':
                for line in list:
                    if not line or not line.startswith('#'):
                        ioc = line.split('\n')
                        ioc = [i for i in ioc if i]
                        urlhaus_list.append(ioc)
                        for id in ioc:
                            urlhaus_ioc = re.split(r',(?=")', id)
                            build_urlhaus_payload(tf, tf_type, urlhaus_ioc[1], urlhaus_ioc[2], urlhaus_ioc[3], urlhaus_ioc[4], urlhaus_ioc[5], urlhaus_ioc[6])
                final_payload = ''.join(indicator_list)
                send_to_splunk(final_payload, tf, splunk_hec_token)
            elif tf == 'AlienVault OTX Reputation data':
                parsed_alienvault_iocs = parse_alienvault_reputation_data(list)
                for av_indicator in parsed_alienvault_iocs:
                    build_payload(av_indicator, tf, tf_type)
                final_payload = ''.join(indicator_list)
                send_to_splunk(final_payload, tf, splunk_hec_token)
            elif tf_type == 'ip':
                validated_ip_list = update_s3_indicators_file(tf_type, i_list)
                for parsed_ioc_ip in validated_ip_list:
                    build_payload(parsed_ioc_ip, tf, tf_type)
                final_payload = ''.join(indicator_list)
                if not final_payload:
                    print(f"no new IPs to send to Splunk")
                else:
                    send_to_splunk(final_payload, tf, splunk_hec_token)
            elif tf_type == 'domain':
                for domain_name in i_list:
                    extracted_domain = re.match(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', domain_name)
                    build_payload(extracted_domain.group(0), tf, tf_type)
                final_payload = ''.join(indicator_list)
                if not final_payload:
                    print(f"no new domains indicators to send to Splunk")
                else:
                    send_to_splunk(final_payload, tf, splunk_hec_token)
            elif tf_type == 'url':
                urls_to_send = update_s3_indicators_file(tf_type, i_list)
                #for url in i_list:
                for url in urls_to_send:
                    build_payload(url, tf, tf_type)
                final_payload = ''.join(indicator_list)
                if not final_payload:
                    print(f"no new URLs to send to Splunk")
                else:
                    send_to_splunk(final_payload, tf, splunk_hec_token)
            elif tf_type == 'hash':
                for hash in i_list:
                    if not hash or hash.startswith('#'):
                        pass
                    else:
                        build_payload(hash, tf, tf_type)
                final_payload = ''.join(indicator_list)
                send_to_splunk(final_payload, tf, splunk_hec_token)
            elif tf_type == 'email':
                for email in i_list:
                    if not email or email.startswith('#'):
                        pass
                    else:
                        build_payload(email, tf, tf_type)
                final_payload = ''.join(indicator_list)
                send_to_splunk(final_payload, tf, splunk_hec_token)
            elif tf_type == 'ipv6':
                for ipv6 in i_list:
                    if not ipv6 or ipv6.startswith('#'):
                        pass
                    else:
                        build_payload(ipv6, tf, tf_type)
                final_payload = ''.join(indicator_list)
                send_to_splunk(final_payload, tf, splunk_hec_token)
            else:
                print(f"Unknown or bad IOC type")
    except Exception:
        print(f"Something went wrong - check feeds file is valid JSON")

if __name__ == "__main__":
    lambda_handler(event, context)
    #tf_type = 'ip'
    #update_s3(tf_type)
