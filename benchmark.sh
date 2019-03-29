#!/bin/bash

function startup_ovs {
    pkill ovs
    echo "Loading kernel module"
    /sbin/modprobe openvswitch
    echo "Starting ovsdb-server"
    ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
    --pidfile --detach --log-file
    ovs-vsctl --no-wait init
    ovs-vswitchd &
}

function add_flows {
    for i in `seq 100`; do
	    ovs-ofctl add-flow br0 actions=normal
	    sleep 0.1
    done
}

source /opt/intel/sgxsdk/environment

pkill ovs

echo "BENCHMARKING NO SGX"

./build.sh

cd ovs

startup_ovs

add_flows

cd ..

echo "BENCHMARKING SGX"

./build.sh "-D SGX" 

cd ovs

startup_ovs

add_flows

cd ..

echo "BENCHMARKING SGX HOTCALL"

./build.sh "-D SGX -D HOTCALL" "-D HOTCALL"

cd ovs

startup_ovs

add_flows

cd ..

echo "BENCHMARKING SGX HOTCALL TIMEOUTS"

./build.sh "-D SGX -D HOTCALL -D TIMEOUT" "-D HOTCALL -TIMEOUT"

cd ovs

startup_ovs

add_flows

cd ..

sleep 1


pkill ovs

