#!/bin/bash
source /opt/intel/sgxsdk/environment
echo "Loading kernel module"
/sbin/modprobe openvswitch
echo "Starting ovsdb-server"
ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
    --pidfile --detach --log-file
ovs-vsctl --no-wait init
echo "Starting ovs-vswitch"
ovs-vswitchd #--pidfile --detach --log-file
