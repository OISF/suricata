FROM centos:latest

# The Suricata version to install. This should match the version in the download
# URL. E.g: https://www.openinfosecfoundation.org/download/suricata-<VERSION>.tar.gz
ENV SURICATA_VERSION '4.0.5'

# The Boost library version to install. This should match the version in the download
# URL. E.g: https://dl.bintray.com/boostorg/release/<VERSION>/source/boost_<VERSION>.tar.gz
ENV BOOST_VERSION '1.67.0'

# The Ragel compiler version to install. This should match the version in the download
# URL. E.g: http://www.colm.net/files/ragel/ragel-<VERSION>.tar.gz
ENV RAGEL_VERSION '6.10'

# YUM packages to install.
ENV YUM_PACKAGES \
    epel-release \
    wget \
    iproute \
    pciutils \
    libpcap \
    libpcre \
    libmagic \
    zlib \
    libyaml \
    make \
    gcc \
    pkg-config \
    libjansson \
    libnss \
    libgeoip \
    liblua5.1 \
    libhiredis \
    libevent \
    rustc \
    cargo \
    pcre-devel \
    libyaml-devel \
    libpcap-devel \
    lua-devel \
    libcap-ng-devel \
    file-devel \
    jansson-devel \
    zlib-devel \
    libhtp \
    wireshark \
    cmake \
    git \
    python-pip

# Tell systemd we're in Docker.
ENV container docker

# Install the YUM packages.
RUN yum -y --enablerepo=extras install epel-release && \
    yum -y update && \
    for i in "${YUM_PACKAGES[@]}"; do yum -y install $i; done && \
    yum -y groupinstall 'Development Tools'

# Build the Ragel compiler.
RUN wget -O /tmp/ragel.tar.gz "http://www.colm.net/files/ragel/ragel-${RAGEL_VERSION}.tar.gz" && \
    tar xzvf /tmp/ragel.tar.gz -C /tmp && \
    cd "/tmp/ragel-${RAGEL_VERSION}" && \
    ./configure && \
    make && \
    make install

# Clone and extract Hyperscan source.
RUN git clone https://github.com/01org/hyperscan /tmp/hyperscan && \
    mkdir -p /tmp/hyperscan/build

# Install Hyperscan build dependencies.
RUN wget -O /tmp/boost.tar.gz "https://dl.bintray.com/boostorg/release/${BOOST_VERSION}/source/boost_$(echo $BOOST_VERSION | tr . _).tar.gz" && \
    tar xzvf /tmp/boost.tar.gz -C /tmp && \
    mv "/tmp/boost_$(echo $BOOST_VERSION | tr . _)/boost" /tmp/hyperscan/include/

# Build Hyperscan.
RUN cd /tmp/hyperscan/build && \
    cmake -DBUILD_STATIC_AND_SHARED=1 ../ && \
    make && \
    make install

# Download and extract Suricata source.
RUN wget -O /tmp/suricata.tar.gz "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" && \
    tar xzvf /tmp/suricata.tar.gz -C /tmp

# TODO: Verify tarball against signature:
# "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz.sig"

# Compile and install Suricata from source.
RUN cd "/tmp/suricata-${SURICATA_VERSION}" && \
    ./configure --enable-geopip --enable-lua && \
    make && \
    make install-full

# Install suricata-update for rule management.
RUN pip install --pre --upgrade pip pyyaml suricata-update

# Cleanup.
RUN yum clean all; \
    rm -rf /var/cache/yum; \
    rm -rf /tmp/*

# Simple entrypoint script to run suricata-update then suricata.
COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

# Finally, run suricata-update and start suricata in the foreground.
# Suricata arguments are provided at the run command.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
