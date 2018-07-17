fswatch . |  xargs -I {} -- rsync -av * root@10.137.0.25:suricata/
