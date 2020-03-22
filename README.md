# dupdup
```
debian/ubuntu：
    apt-get install libnet1-dev
    apt-get install libpcap0.8-dev 

centos： 
    wget http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
    rpm -ivh epel-release-6-8.noarch.rpm
    yum install libnet libpcap libnet-devel libpcap-devel

build:
    sh build.sh

usage:
    # 100% when bandwidth in range [0, 512] kb/s, 50% when bandwidth in range [512, 1024] kb/s.
    ethtool -K eth0 tso off
    ./dupdup eth0 "ip" 512 1024
    ./dupdup eth0 "tcp src port 443" 512 1024
    
```
