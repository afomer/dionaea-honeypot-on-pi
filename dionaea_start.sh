#!/bin/bash
sudo /opt/dionaea/bin/dionaea -D -c /opt/dionaea/etc/dionaea/dionaea.conf  -r /opt/dionaea -w /opt/dionaea -p /opt/dionaea/var/dionaea.pid -l all,-debug -L '*'
sudo /opt/dionaea/bin/connection_logs_reader.py &


