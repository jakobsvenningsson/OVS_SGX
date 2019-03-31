ovs-vsctl -- add-br br0 -- set bridge br0 datapath-type=dummy other-config:datapath-id=fedcba9876543210 other-config:hwaddr=aa:55:aa:55:00:00 protocols=[OpenFlow10,OpenFlow12,OpenFlow13] fail-mode=secure -- add-port br0 p1 -- set Interface p1 type=dummy ofport_request=1

#ovs-ofctl add-flow br0 'actions=learn(fin_hard_timeout=10, fin_idle_timeout=5, NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[], output:NXM_OF_IN_PORT[])'
