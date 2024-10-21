sudo apt update
sudo apt install -y build-essential gcc make perl dkms
sudo apt install -y bluez-tools
sudo apt install -y python2 python2-dev
sudo apt install -y python-pip
sudo apt install -y graphviz libgraphviz-dev
sudo apt install -y adb scrcpy

sudo /usr/bin/python2.7 -m pip install \
setuptools \
python-engineio==3.11.2 \
python-socketio==4.4.0 

sudo /usr/bin/python2.7 -m pip install \
pyserial==3.4 \
pyrecord==1.0.1 \
psutil==5.6.3 \
numpy==1.16 \
Flask==0.11.1 \
pygraphviz==1.5 \
colorama==0.4.1 \
cryptography==2.7 \
pycryptodome==3.8.2 \
socketio==0.1.7 \
ddt==1.2.1 \
mock==3.0.5 \
Flask-SocketIO==4.1.0 \
logbook==1.4.4 \
gevent==1.2.2 \
pycallgraph==1.0.1 \
pygmo==2.10 \
socketIO-client==0.7.2 \
pydot==1.4.2 \
pydot-ng==2.0.0

echo "DONE..."
