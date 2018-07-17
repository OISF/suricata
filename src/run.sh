fswatch . |  xargs -I {} -- rsync -av * root@172.29.0.147:suricata/src
