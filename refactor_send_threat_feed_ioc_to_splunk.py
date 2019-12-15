import warnings
import ipaddress
import json
import re
import os
import requests
#import iocextract
import boto3

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
hec_endpoint = 'http://127.0.0.1:8088/services/collector'
splunk_hec_token = 'aabc8410-f63e-4ba7-9d68-a166d4a0e699'
indicator_list = []
list = []
urlhaus_list = []
file = 'feeds.json'
s3_bucket = 'ah-open-source-threat-feeds-test-bucket'
#s3_bucket = 'cyber-security-open-source-threat-feed-indicators'
s3_talos_ip_filename = 'cisco_talos.txt'
s3_tor_ip_filename = 'tor_exit_nodes.txt'
s3_domain_filename = 'domain.txt'
s3_url_filename = 'url.txt'
s3_urlhaus_filename = 'urlhaus.txt'
event = ''
context = ''

""" Get Splunk HEC token from SSM Parameter Store  """
#ssm_client = boto3.client('ssm', region_name='eu-west-2')

def get_ssm_parameter(param):
    ssm_response = ssm_client.get_parameter(
        Name=str(param),
        WithDecryption=True
        )
    return ssm_response['Parameter']['Value']

""" Remove duplicate indicators """
def check_dupes(list_to_dedupe):
    deduped_list = set(); return [dupe_ioc for dupe_ioc in list_to_dedupe if dupe_ioc not in deduped_list and not deduped_list.add(dupe_ioc)]
    return deduped_list

""" Update indicator file in S3 """
def update_s3_indicators_file(tf, tf_type, i_list):
    s3 = boto3.resource('s3')
    try:
        """ Update Cisco Talos indicator list """
        if tf == 'Cisco Talos blacklist' and tf_type == 'ip':
            pass
            s3.meta.client.download_file(s3_bucket, s3_talos_ip_filename, '/tmp/' + s3_talos_ip_filename)

            with open('/tmp/' + s3_talos_ip_filename, 'r+') as talos_ro_fn:
                old_talos_ip_list = talos_ro_fn.read().splitlines()
            talos_ro_fn.close()

            """ Get updates Cisco Talo indicators and remove duplicates """
            updated_talos_ip_list = [talos_ip_item for talos_ip_item in i_list if talos_ip_item not in old_talos_ip_list]
            deduped_talos_ip_list = check_dupes(updated_talos_ip_list)

            with open('/tmp/' + s3_talos_ip_filename, 'a') as talos_append_fn:
                for new_talos_ip in deduped_talos_ip_list:
                    talos_append_fn.write(new_talos_ip + '\n')
            talos_append_fn.close()

            """ Upload updated Cisco Talos indictators file to S3 """
            s3.meta.client.upload_file('/tmp/' + s3_talos_ip_filename, s3_bucket, s3_talos_ip_filename)

            """ Remove temp file """
            os.remove('/tmp/' + s3_talos_ip_filename)

            return deduped_talos_ip_list

        elif tf == 'Tor exit nodes' and tf_type == 'ip':
            s3.meta.client.download_file(s3_bucket, s3_tor_ip_filename, '/tmp/' + s3_tor_ip_filename)

            with open('/tmp/' + s3_tor_ip_filename, 'r+') as tor_ro_fn:
                old_tor_ip_list = tor_ro_fn.read().splitlines()
            tor_ro_fn.close()

            updated_tor_ip_list = [tor_ip_item for tor_ip_item in i_list if tor_ip_item not in old_tor_ip_list]
            deduped_tor_ip_list = check_dupes(updated_tor_ip_list)

            with open('/tmp/' + s3_tor_ip_filename, 'a') as tor_append_fn:
                for new_tor_ip in deduped_tor_ip_list:
                    tor_append_fn.write(new_tor_ip + '\n')
            tor_append_fn.close()

            s3.meta.client.upload_file('/tmp/' + s3_tor_ip_filename, s3_bucket, s3_tor_ip_filename)
            os.remove('/tmp/' + s3_tor_ip_filename)

            return deduped_tor_ip_list

        elif tf_type == 'url' and not tf == 'URLHaus':
            s3.meta.client.download_file(s3_bucket, s3_url_filename, '/tmp/' + s3_url_filename)

            with open('/tmp/' + s3_url_filename, 'r+') as url_ro_fn:
                old_url_list = url_ro_fn.read().splitlines()
            url_ro_fn.close()

            updated_url_list = [url_item for url_item in i_list if url_item not in old_url_list]
            deduped_url_list = check_dupes(updated_url_list)

            with open('/tmp/' + s3_url_filename, 'a') as url_append_fn:
                for new_url in deduped_url_list:
                    url_append_fn.write(new_url + '\n')
            url_append_fn.close()

            s3.meta.client.upload_file('/tmp/' + s3_url_filename, s3_bucket, s3_url_filename)
            os.remove('/tmp/' + s3_url_filename)

            return deduped_url_list

        elif tf_type == 'domain':
            s3.meta.client.download_file(s3_bucket, s3_domain_filename, '/tmp/' + s3_domain_filename)

            with open('/tmp/' + s3_domain_filename, 'r+') as domain_ro_fn:
                old_domain_list = domain_ro_fn.read().splitlines()
            domain_ro_fn.close()

            updated_domain_list = [domain_item for domain_item in i_list if domain_item not in old_domain_list]
            deduped_domain_list = check_dupes(updated_domain_list)

            with open('/tmp/' + s3_domain_filename, 'a') as domain_append_fn:
                for new_domain in deduped_domain_list:
                    domain_append_fn.write(new_domain + '\n')
            domain_append_fn.close()

            s3.meta.client.upload_file('/tmp/' + s3_domain_filename, s3_bucket, s3_domain_filename)
            os.remove('/tmp/' + s3_domain_filename)

            return deduped_domain_list

        elif tf == 'URLHaus':
            s3.meta.client.download_file(s3_bucket, s3_urlhaus_filename, '/tmp/' + s3_urlhaus_filename)

            with open('/tmp/' + s3_urlhaus_filename, 'r+') as urlhaus_ro_fn:
                old_urlhaus_list = urlhaus_ro_fn.read().splitlines()
            urlhaus_ro_fn.close()

            updated_urlhaus_list = [urlhaus_item for urlhaus_item in i_list if urlhaus_item not in old_urlhaus_list]
            deduped_urlhaus_list = check_dupes(updated_urlhaus_list)

            with open('/tmp/' + s3_urlhaus_filename, 'a') as urlhaus_append_fn:
                for new_urlhaus in deduped_urlhaus_list:
                    urlhaus_append_fn.write(new_urlhaus + '\n')
            urlhaus_append_fn.close()

            s3.meta.client.upload_file('/tmp/' + s3_urlhaus_filename, s3_bucket, s3_urlhaus_filename)
            os.remove('/tmp/' + s3_urlhaus_filename)

            return deduped_urlhaus_list
        else:
            pass
    except:
        print(f"Unable to update indicators file stored in S3")

""" Parse IOC (Indicators of Compromise) """
def parse_ioc(feed_list, tf, tf_type):
    feed_ioc_list = [i for i in feed_list if '#' not in i]
    if tf_type == 'ip':
        validated_ip = validate_ipaddress(feed_ioc_list)
        updated_ip_list = update_s3_indicators_file(tf, tf_type, validated_ip)

        for parsed_ip in updated_ip_list:
            build_payload(parsed_ip, tf, tf_type)
        final_ip_payload = ''.join(indicator_list)

        return final_ip_payload

    elif tf_type == 'url' and not tf == 'URLHaus':
        updated_url_list = update_s3_indicators_file(tf, tf_type, feed_ioc_list)

        for parsed_url_ioc in updated_url_list:
            build_payload(parsed_url_ioc, tf, tf_type)
        final_url_payload = ''.join(indicator_list)

        return final_url_payload

    elif tf_type == 'domain':

        updated_domain_list = update_s3_indicators_file(tf, tf_type, feed_ioc_list)

        for parsed_domain_ioc in updated_domain_list:
            build_payload(parsed_domain_ioc, tf, tf_type)
        final_domain_payload = ''.join(indicator_list)

        return final_domain_payload

    elif tf == 'URLHaus':
        parsed_urlhaus_list = []
        for line in feed_ioc_list:
            if not line or not line.startswith('#'):
                ioc = line.split('\n')
                ioc = [i for i in ioc if i]
                urlhaus_list.append(ioc)
                for id in ioc:
                    urlhaus_ioc = re.split(r',(?=")', id)
                    parsed_urlhaus_list.append(id)

        updated_urlhaus_list = update_s3_indicators_file(tf, tf_type, parsed_urlhaus_list)
        urlhaus_payload = build_urlhaus_payload(tf, tf_type, updated_urlhaus_list)
        final_urlhaus_payload = ''.join(urlhaus_payload)

        return final_urlhaus_payload

    else:
        pass

""" Download indicators from Open Source Threat Feeds """
def download_ioc_from_feed(url):
    try:
        response = requests.get(url)
        data = response.text
        ioc_list = data.splitlines()
        return ioc_list
    except Exception:
        print(f"URL fetch error: {response.text}")

""" Validate an IP address or IP range but not CIDR """
def validate_ipaddress(ip):
    try:
        range_of_ips = []
        stripped_cidr = [ioc_ip for ioc_ip in ip if '/' not in ioc_ip]
        """ we are not processing CIDR at the moment as they could be huge """
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


""" build IOC payload for Splunk """
def build_payload(ioc, tf, tf_type):
    payload = '{"sourcetype": "_json", "event": {"feed": "' + tf + '","indicator_type": "' + tf_type + '","indicator":"' + ioc + '"}}'
    #print(payload)
    indicator_list.append(payload)
    return indicator_list


""" build URLHaus payload for Splunk """
def build_urlhaus_payload(tf, tf_type, updated_urlhaus_indicators):
    #print(updated_urlhaus_indicators)
    for urlhaus_ioc in updated_urlhaus_indicators:
        #print(urlhaus_ioc)
        urlhaus_ioc = re.split(r',(?=")', urlhaus_ioc)
        payload = '{"sourcetype": "_json", "event": {"feed": "' + tf + '","indicator_type": "' + tf_type + '","indicator": ' + urlhaus_ioc[2] + ',"status": ' + urlhaus_ioc[3] + ', "threat": ' + urlhaus_ioc[4] + ',"tags": ' + urlhaus_ioc[5] + ',"date_added": ' + urlhaus_ioc[1] + ',"urlhaus_url": ' + urlhaus_ioc[6] + '}}'
        #print(payload)
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
            list = []
            tf = threat_feed['feed_name']
            tf_type = threat_feed['feed_type']
            tf_url = threat_feed['feed_url']

            if tf == 'URLHaus' and tf_type == 'url':
                #print('yep')
                #parsed_urlhaus_list = []
                urlhaus_feed_list = download_ioc_from_feed(tf_url)
                final_urlhaus_payload = parse_ioc(urlhaus_feed_list, tf, tf_type)

                #print(final_urlhaus_payload)
                if not final_urlhaus_payload:
                    print(f"No new URLHaus indicators to send to Splunk")
                else:
                    send_to_splunk(final_urlhaus_payload, tf, splunk_hec_token)

            elif tf == 'Cisco Talos blacklist' and tf_type == 'ip':
                talos_feed_list = download_ioc_from_feed(tf_url)
                final_talos_payload = parse_ioc(talos_feed_list, tf, tf_type)

                if not final_talos_payload:
                    print(f"No new Cisco Talos indicators to send to Splunk")
                else:
                    send_to_splunk(final_talos_payload, tf, splunk_hec_token)

            elif tf == 'Tor exit nodes' and tf_type == 'ip':
                tor_feed_list = download_ioc_from_feed(tf_url)
                final_tor_payload = parse_ioc(tor_feed_list, tf, tf_type)

                if not final_tor_payload:
                    print(f"No new Tor exit node indicators to send to Splunk")
                else:
                    send_to_splunk(final_tor_payload, tf, splunk_hec_token)

            elif tf_type == 'domain':
                tmp_domain_list = []
                domain_feed_list = download_ioc_from_feed(tf_url)

                for validate_domain in domain_feed_list:
                    extracted_domain = re.match(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', validate_domain)
                    if bool(extracted_domain) == True:
                        tmp_domain_list.append(extracted_domain.group(0))
                    else:
                        print('invalid domain')
                        pass

                final_domain_payload = parse_ioc(tmp_domain_list, tf, tf_type)

                if not final_domain_payload:
                    print(f"No new domains indicators to send to Splunk")
                else:
                    send_to_splunk(final_domain_payload, tf, splunk_hec_token)

            elif tf_type == 'url' and not tf == 'URLHaus':
                url_feed_list = download_ioc_from_feed(tf_url)
                final_url_payload = parse_ioc(url_feed_list, tf, tf_type)

                if not final_url_payload:
                    print(f"No new URL indicators to send to Splunk")
                else:
                    send_to_splunk(final_url_payload, tf, splunk_hec_token)

            elif tf_type == 'hash':
                pass

            elif tf_type == 'email':
                pass

            else:
                print(f"Unknown or bad IOC type")

    except Exception:
        print(f"Something went wrong - check feeds file is valid JSON")


if __name__ == "__main__":
    lambda_handler(event, context)
