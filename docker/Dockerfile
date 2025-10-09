# Use Ubuntu as base image
FROM ubuntu:22.04

# Install Suricata and Python
RUN apt-get update && \
    apt-get install -y software-properties-common python3 python3-pip git && \
    add-apt-repository ppa:oisf/suricata-stable && \
    apt-get update && \
    apt-get install -y suricata

# Create required directories
RUN mkdir -p /var/log/suricata && \
    mkdir -p /var/run/suricata

# Install suricata-update from source
RUN git clone --branch 1.3.6 https://github.com/OISF/suricata-update.git /tmp/suricata-update && \
    cd /tmp/suricata-update && \
    python3 setup.py install

# Copy and install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN grep -v "suricata-update" /tmp/requirements.txt > /tmp/filtered-requirements.txt && \
    pip3 install -r /tmp/filtered-requirements.txt

# Copy configuration
COPY suricata.yaml.in /etc/suricata/suricata.yaml

# Expose ports
EXPOSE 443

# Set the entrypoint
CMD ["/usr/bin/suricata", "-c", "/etc/suricata/suricata.yaml", "--af-packet"]