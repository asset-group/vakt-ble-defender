#!/usr/bin/env bash

# System packages
sudo mkdir -p /usr/share/man/man1 # make sure man1 dir exists
sudo apt-get install git build-essential python-pip python-dev graphviz libgraphviz-dev libssl-dev \
pciutils kmod wireless-tools net-tools dnsmasq iproute2 iptables aircrack-ng freeradius python-matplotlib -y
# Kernel header & wifi subsytem
if [ -z "$RUNNING_DOCKER" ]
then
	sudo apt install linux-headers-$(uname -r) linux-modules-extra-$(uname -r) -y
fi

set -e # exit on error
# Python packages
sudo python -m pip install pip setuptools Flask-SocketIO==3.3.2 -U
sudo python -m pip install -r requirements.txt -U

# Build python modules
sh -c "cd wifi/eap_module && make && sudo make install"
sh -c "cd bluetooth/smp_server/ && make && sudo make install"

# Build custom wifi kernel driver (RT2800USB)
if [ -z "$RUNNING_DOCKER" ]
then
	if [[ $(uname -r) == "5."* ]]
	then
		echo "Building Wi-Fi driver for Linux Kernel 4.X"
  		sh -c "cd drivers/RT2800_v5/ && make && sudo make install insert" || true
  	else
  		echo "Building Wi-Fi driver for Linux Kernel 5.X"
  		sh -c "cd drivers/RT2800_v4/ && make && sudo make install insert" || true
  	fi
fi

# Configure freeradius
sudo cp wifi/freeradius_config/* /etc/freeradius/3.0/ -R # Copy freeradius configuration files (peap by default)
sudo sed -i "s/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/" /etc/ssl/openssl.cnf # Make ssl accept unsecure certificates
sudo sed -i "s/CipherString = DEFAULT@SECLEVEL=2/CipherString = DEFAULT@SECLEVEL=1/" /etc/ssl/openssl.cnf # Make ssl accept unsecure certificates
set +e # ignore on error
sudo service freeradius restart || true
sudo chmod g+w /var/run/freeradius/freeradius.pid # Make sure freeradius group has write permission
sync
sudo service freeradius start

echo -e "\n"

exit 0
