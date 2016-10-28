# Building DPDK support for Surricata
DPDK is an open source set of drivers to support fast packet processing and is well supported on Intel NICs. These instructions will walk through building and integrating DPDK into Suricata.

## Install Dependencies for building DPDK and Suricata
```
yum install automake autoconf git libtool make gcc gcc-c++ libyaml-devel libpcap-devel pcre-devel file-devel zlib-devel jansson-devel nss-devel libcap-ng-devel libnet-devel libnetfilter_queue-devel lua-devel which bzip2-devel GeoIP-devel python-pyelftools GeoIP-devel cmake
```

If you wouldl like to create an RPM for suricata, you install FPM.
```
yum install ruby ruby-libs ruby-irb rubygems ruby-devel
gem install fpm 
```

## Build and Install DPDK RPM
The following steps will build and install DPDK onto your development system

**NOTE:** At time of this writing the patches only support DPDK 2.2. Work is ongoing to support new versions of DPDK.

```
curl -O http://dpdk.org/browse/dpdk/snapshot/dpdk-2.2.0.tar.gz
mkdir -p ~/rpmbuild/SOURCES
cp dpdk-2.2.0.tar.gz ~/rpmbuild/SOURCES/
curl -O https://raw.githubusercontent.com/edsealing/suricata/3.1.2-dpdk/pkg/dpdk-suricata.spec
rpmbuild -bb ./dpdk-suricata.spec
cp ~/rpmbuild/RPMS/x86_64/
```

## Build Suricata RPM
These instructions will be for building a suricata RPM that includes Hyperscan and DPDK support. Please modify as needed to fit your use case.

### Download and build Boost
Boost does not need to be installed on the system directly. It will be temporarily installed to /tmp/boost-1.60. This directory can be removed after suricata has been built (as it's rather large).
```
curl -O	http://downloads.sourceforge.net/project/boost/boost/1.60.0/boost_1_60_0.tar.gz
tar xzf boost_1_60_0.tar.gz
mkdir /tmp/boost-1.60
cd boost_1_60_0
./bootstrap.sh --prefix=/tmp/boost-1.60
./b2 install
```

### Download and build ragel RPM
```
wget http://www.colm.net/files/ragel/ragel-6.9.tar.gz
tar xvzf ragel-6.9.tar.gz
cd ragel-6.9
./configure --prefix=/usr
make
mkdir /tmp/ragel
make install
make install DESTDIR=/tmp/ragel
fpm --prefix=/ -s dir -t rpm -n ragel -v 6.9 -C /tmp/ragel -p
```

### Download and build Hyperscan RPM
```
git clone https://github.com/01org/hyperscan
cd hyperscan/
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/tmp/hyperscan -DBUILD_STATIC_AND_SHARED=1 -DBOOST_ROOT=/tmp/boost-1.60/ ../
make
make install
fpm --prefix=/ -s dir -t rpm -n hyperscan -v 4.3.1 -d 'ragel' -C /tmp/hyperscan -p
```

### Install Hyperscan and ragel RPMs
```
yum localinstall ragel-6.9.x86_64.rpm hyperscan-4.3.1.x86_64.rpm
```

### Build Suricata with DPDK and Hyperscan
```
git clone -b 3.1.2-dpdk https://github.com/edsealing/suricata.git
cd suricata
git clone https://github.com/OISF/libhtp
autogen.sh
export RTE_SDK=~/dpdk-2.2.0/
export RTE_TARGET=x86_64-native-linuxapp-gcc
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-nfqueue --with-libhs-libraries=/usr/lib/ --with-libhs-includes=/usr/include/hs/ --enable-lua --enable-geoip --enable-dpdkintel --with-libdpdkintel-includes=/usr/include/dpdk/ --with-libdpdkintel-libraries=/root/dpdk-2.2.0/x86_64-native-linuxapp-gcc/lib
make
```

### Create Suricata RPM
```
mkdir /tmp/suricata
make install-full DESTDIR=/tmp/suricata
fpm --prefix=/ -s dir -t rpm -n suricata-dpdk -v 3.1.2 -C /tmp/suricata/ -p suricata-dpdk-3.1.2.x86_64.rpm
```
