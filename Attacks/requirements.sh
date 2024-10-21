
# Change to current script folder
CURRENT_PATH="$(readlink -e $(dirname ${BASH_SOURCE[0]:-$0}))"
cd $CURRENT_PATH

# InjectaBLE requirements
echo '----------- Intalling InjectaBLE -----------'
cd $CURRENT_PATH/Non-Sweyntooth/injectable
sudo apt install -y python3-venv python3-dev
python3 -m venv venv
source venv/bin/activate
python3 setup.py install
pip3 install nrfutil
echo '----------------------------------------'
echo 'InjectaBLE done!'

# Sweyntooth Attacks and CyRC requirements
echo '----------- Intalling Sweyntooth Attacks and CyRC -----------'
cd $CURRENT_PATH/Sweyntooth
sudo apt update && sudo apt install build-essential
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
cd libs/smp_server/
CC=gcc CXX=g++ python3 setup.py install
echo '----------------------------------------'
echo 'Sweyntooth Attacks done!'

# Sweyntooth Fuzzer and BLEDiff requirements
echo '----------- Intalling Sweyntooth Fuzzer and BLEDiff -----------'
cd $CURRENT_PATH/Non-Sweyntooth/BLEDiff
./requirements.sh
cd bluetooth/smp_server
CC=gcc CXX=g++ make
echo '----------------------------------------'
echo 'Fuzzer and BLEDiff done!!'
