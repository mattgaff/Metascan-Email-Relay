#!/bin/bash

tar -jxvf metascan_relay.tar.bz2 -C /opt
echo '/opt/metascan_relay/metascan_relay.sh' >> /etc/rc.local
chkconfig sendmail off
