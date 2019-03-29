#!/bin/bash
source /opt/intel/sgxsdk/environment
/sbin/modprobe openvswitch
ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
    --pidfile --detach --log-file
ovs-vsctl --no-wait init
ovs-vswitchd
