#!/usr/bin/python
"""
dnsSniff.py:    Simple DNS sniffer that outputs data to a text file (output.txt)

"""
Credit to /u/corifeo for main source code

from datetime import datetime
import logging
from scapy.all import *

interface="ens33"
logfile="output.txt"

def dns_parser(data):
  if data.haslayer(DNS) and data.haslayer(DNSQR):
    ip = data.getlayer(IP)
    udp = data.getlayer(UDP)
    dns = data.getlayer(DNS)
    dnsqr = data.getlayer(DNSQR)
    now = datetime.now()
    timestamp = str(now.strftime('%d-%b-%Y %H:%M:%S.%f'))
    query = dnsqr.sprintf("%qname% %qclass% %qtype%").replace("'","")+ " +"
    log = '%s client %s#%s: query: %s (%s)' % (timestamp[:-3], ip.src, udp.sport, \
          query, ip.dst)
    logging.info(log)

if __name__ == '__main__':
 
  logging.basicConfig(filename=logfile, format='%(message)s', level=logging.INFO)
  console = logging.StreamHandler()
  logging.getLogger('').addHandler(console)

  try:
    sniff(filter="udp dst port 53", prn=dns_parser, store=0, iface=interface)
  except KeyboardInterrupt:
    exit(0)
