#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

circl_url = 'https://www.circl.lu/doc/misp/feed-osint/'
urlhaus_url = 'https://urlhaus.abuse.ch/downloads/csv'

def get_latest_circl_feed(circl_url):
    page = requests.get(circl_url).text
    soup = BeautifulSoup(page, 'html.parser')
    circl_file_list = []
    tags = soup.find_all('a')

    for tag in tags:
        circl_file_list.append(str(tag.get('href')))
        for x in circl_file_list:
            if x[-4:] == 'json':
                fn = x
                break

    latest_circl_file = requests.get(circl_url + '/' + fn).text
    print(latest_circl_file)



def get_latest_urlhaus_feed(urlhaus_url):
    page2 = requests.get(urlhaus_url).text
    ioc_list = page2.splitlines()
    print(ioc_list)
    """
    for line in ioc_list:
      ioc = line.split(',')
      ioc_timestamp = ioc[1]
      ioc_url = ioc[2]
      ioc_status = ioc[3]
      ioc_threat = ioc[4]
      ioc_tags = ioc[5]
      print(f"ioc timestamp:{ioc_timestamp} url: {ioc_url} status: {ioc_status} threat: {ioc_threat} tags: {ioc_tags}")
    """
    

"""
def parse_website(url):
        try:
                response = requests.get(url)
                #data = response.text
                data = response.json
                ioc_list = data.splitlines()
                return ioc_list
        except Exception:
                print(f"URL fetch error: {response.text}")

"""
def main():
	#foo = get_latest_circl_feed(circl_url)
	get_latest_urlhaus_feed(urlhaus_url)
	#print(foo)

if __name__ == "__main__":
        main()
