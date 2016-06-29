#!/usr/bin/python
## This program intend to send the info of each new connection to elasticsearch, created by intern: Abubaker Omer ##

import re
from datetime import datetime
from elasticsearch import Elasticsearch
import pygeoip
#### The main Function to send to elasticsearch ####
# The current ip:192.168.100.15, port:9200
# requires the info of the log in one line. Detalis are separated by spaces
# example: 1465246790.0 connection 1 httpd tcp accept 192.168.100.4:80 <- 192.168.100.4:33140 (1, None)
def send_to_es(event_log):

    # Set elasticsearch server info	
	es = Elasticsearch(
		['192.168.100.15'],
		port=9200)

    # Format the event in an array
	event_log = event_log.strip().split()
	#print(event_log)
	# Get the Geoip of the attacker, if possible
	remote_host_country = "Unknown Country"
	
	remote_host_geoip = re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",event_log[8]) # checking min validatiy of the ip
	
	try:
		if remote_host_geoip is not None:
			remote_host_geoip = remote_host_geoip.group()
			GEOIP = pygeoip.GeoIP("/usr/share/GeoIP/GeoIP.dat", pygeoip.MEMORY_CACHE)
		
			if GEOIP.country_name_by_addr(remote_host_geoip):
				remote_host_country = GEOIP.country_name_by_addr(remote_host_geoip)
	except:
		pass
	
	# Formate the attack like JSON
	attackbody_in_json = { 'connection_time' :  event_log[0]  ,
	 'connection_protocol' : event_log[3]  ,
	 'connection_transport' :  event_log[4]  ,
	 'connection_response' : event_log[5] ,
	 'local_host' :  event_log[6] ,
	 'remote_host' :  event_log[8] ,
	 'remote_host_country' : remote_host_country,
	 'timestamp': datetime.now() }
    
	# Formating the index is like default logstash (logstash-"year.month.day")
	# The id of the attack is the number of the attack in the log
	try:
		res = es.index(index="logstash"+datetime.now().strftime("-%Y.%m.%d") , doc_type='json', id = event_log[2], body=attackbody_in_json)
		#print(res['created'])

		es.indices.refresh(index="logstash"+datetime.now().strftime("-%Y.%m.%d") )
		res = es.search(index="logstash"+datetime.now().strftime("-%Y.%m.%d"), body={"query": {"match_all": {}}})
		#print("Got %d Hits:" % res['hits']['total'])

	except:
		pass
	
	
