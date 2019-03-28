
echo "%%%%%%%%%%%%%%%%%%%%%%%%% BUILDING OFTonSGX"

make clean
make SGX_MODE=HW SGX_PRERELEASE=1 SGX_DEBUG=0 LFLAGS="-D HOTCALL"
cp myenclave.signed.so ovs

echo "%%%%%%%%%%%%%%%%%%%%%%%%% BUILDING OvS"
cd ovs
#./boot.sh
./configure CFLAGS="-D SGX -I/home/jakob/OVS_SGX/untrusted" \
            LDFLAGS="-L/home/jakob/OVS_SGX/ovs/lib/ \
                     -L/home/jakob/OVS_SGX" \
            LIBS="-lOFTonSGX -lpthread -lstdc++"
make clean
make
make install
make modules_install
mkdir -p /usr/local/etc/openvswitch
ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema
cd ..
cd ..
