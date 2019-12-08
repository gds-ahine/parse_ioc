#!/usr/bin/env python3

"""
Get Last updated timestamp for URLhaus threat feed
Generate list of IOC id created since last ingest
"""

from requests import get
import datetime
import re
from io import StringIO

url = "https://urlhaus.abuse.ch/downloads/csv"
headers = {"Range": "bytes=0-380"}

r = get(url, headers=headers)
content = r.text
#print(r.text)

s = StringIO(content)

for line in s.readlines():
  if not line:
    break
  if '#' not in line:
    parse_id = line.split(',')

latest_id = parse_id[0].strip('"')
last_id = '264980'
id_diff = int(latest_id) - int(last_id)

print(f"previous id: {last_id}")
print(f"latest id: {latest_id}")
print(f"diff between latest id and previously ingested id is {id_diff}")

for x in range(int(last_id),int(latest_id)+1):
	print(f"id: {x}")

ts_now = datetime.datetime.now()
current_ts = ts_now.strftime('%Y-%m-%d %H:%M:%S')

#last_updated = re.search(r'Last\supdated:\s\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',content)
last_updated = re.search(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',content)
file_ts  = datetime.datetime.strptime(str(last_updated.group()), '%Y-%m-%d %H:%M:%S')
#file_ts  = datetime.datetime.strptime(str(last_updated), '%Y-%m-%d %H:%M:%S')
s_diff = ts_now - file_ts
#print(s_diff.days)

#if s_diff.days >= 1:
#	print(f"file last updated {s_diff.days} day(s) ago")
#	print(f"Downloading latest file...")
#	req = get(url)
		


