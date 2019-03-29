#!/bin/bash

pkill ovs

echo "Benchmarking baseline"

./build.sh "-D SGX"

cd ovs

./startup.sh 

for i in `seq 100`; do
	ovs-ofctl add-flow br0 actions=normal
	sleep 0.1
done


pkill ovs


