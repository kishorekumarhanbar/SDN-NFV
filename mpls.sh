echo "Setting Switches to work with OpenFlow 1.3"
for i in s1 s2 s3; do
    sudo ovs-vsctl set bridge $i protocols=OpenFlow13
done
  # Clear flow tables
echo "Clearing Flow tables.."
for i in s1 s2 s3; do
    sudo ovs-ofctl -O OpenFlow13 del-flows $i
done
    #Configure switches with a unique ID
echo "Setting switches ID"
    sudo ovs-vsctl set bridge s1 other-config:datapath-id=0000000000000001
    sudo ovs-vsctl set bridge s2 other-config:datapath-id=0000000000000002
    sudo ovs-vsctl set bridge s3 other-config:datapath-id=0000000000000003
