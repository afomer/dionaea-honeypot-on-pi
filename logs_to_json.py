import re
from geoip import geolite2
from datetime import datetime
from elasticsearch import Elasticsearch
es = Elasticsearch()

# import dionaea logs file and read the logs line by line
file = open("/opt/dionaea/var/log/connections_log.txt" ,"r")

event_log = file.readline().strip().split()

# Expected Format
#['1465246790.0', 'connection', '1', 'httpd', 'tcp', 'accept', '192.168.100.4:80', '<-', '192.168.100.4:33140', '(1', 'None)']

# Get the Geoip of the attacker, if possible
remote_host_country = "Unknown Country"

remote_host_geoip = re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",event_log[8])

if remote_host_geoip is not None:
	remote_host_geoip = remote_host_geoip.group()

	if geolite2.lookup(remote_host_geoip) is not None:
		remote_host_country = geolite2.lookup(remote_host_geoip).country

while event_log:
	log_body = { 'connection_time' :  event_log[0]  ,
     'connection_protocol' : event_log[3]  ,
     'connection_transport' :  event_log[4]  ,
     'connection_response' : event_log[5] ,
     'local_host' :  event_log[6] ,
     'remote_host' :  event_log[8] ,
     'remote_host_country' : remote_host_country,
     'timestamp': datetime.now()}
	
	res = es.index(index="logstash"+datetime.now().strftime("-%Y.%m.%d") , doc_type='json', id = event_log[2], body=log_body)
	print res['created']
	print log_body
	event_log = file.readline().strip().split()

	res = es.search(index="logstash"+datetime.now().strftime("-%Y.%m.%d"), body={"query": {"match_all": {}}})
#	print("Got %d Hits:" % res['hits']['total'])
#	for hit in res['hits']['hits']:
#   		print("%(timestamp)s %(author)s: %(text)s" % hit["_source"])
	es.indices.refresh(index="logstash"+datetime.now().strftime("-%Y.%m.%d") )

	print res
file.close()
#while event_log:
#	log_in_json = " { 'connection_time' : " + event_log[0] + ' , ' +
#	"'connection_protocol' : " + event_log[3] + ' , ' +
#	"'connection_transport' : " + event_log[4] + ' , ' +
#	"'connection_response' : " + event_log[5] + ' , ' +
#	" 'local_host' : " + event_log[6] + ' , ' +
#        " 'remote_host' : "  + event_log[8] + ' , ' +
#	" 'remote_host_country' : " + remote_host_country + " } "
