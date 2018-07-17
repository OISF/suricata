fswatch . |  xargs -I {} -- rsync -av * cornerstone03:suricata/

# Then
#export SC_LOG_LEVEL=Debug
#export SC_LOG_OP_FILTER="vxlan|decodeudp"
#make && ./src/suricata -u -l /tmp -U ".*VXLAN.*" --fatal-unittests
