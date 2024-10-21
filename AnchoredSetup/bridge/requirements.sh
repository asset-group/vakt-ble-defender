 #!/usr/bin/env bash

ARCH="$(uname -m)"
PYTHON="$(pwd)/runtime/python/install/bin/python3.8"
PIP="$(pwd)/runtime/python/install/bin/python3.8 -m pip"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PYTHON_URL=https://github.com/indygreg/python-build-standalone/releases/download/20230116/cpython-3.8.16+20230116-${ARCH}-unknown-linux-gnu-lto-full.tar.zst
if [ $ARCH == "x86_64" ]
then
    WDISSECTOR_URL=https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks/releases/download/v1.2.0/wdissector_x86_64.tar.zst
else
    WDISSECTOR_URL=https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks/releases/download/v1.2.0/wdissector_aarch64.tar.zst
fi

# Change to current script folder
CURRENT_PATH="$(readlink -e $(dirname ${BASH_SOURCE[0]:-$0}))"
cd $CURRENT_PATH

sudo apt update

# Install zstd
if ! which wget > /dev/null;
then
    echo "package wget not found, installing now..."
    sudo apt install -y wget
else
    echo "wget found!"
fi

# Install zstd
if ! which zstd > /dev/null;
then
    echo "package zstd not found, installing now..."
    sudo apt install -y zstd
else
    echo "zstd found!"
fi

# Install pv
if ! which pv > /dev/null;
then
    echo "package pv not found, installing now..."
    sudo apt install -y pv
else
    echo "pv found!"
fi

# Install uhubctl
if ! which uhubctl > /dev/null;
then
    echo "package uhubctl not found, installing now..."
    sudo apt-get install -y libusb-1.0-0-dev
    git clone https://github.com/mvp/uhubctl
    cd uhubctl
    make
    sudo make install
    sudo ldconfig
    cd ..
else
    echo "uhubctl found!"
fi

# Download wdissector
if [[ ! -d "wdissector" ]]
then
    echo -e "${GREEN}[1/5]${YELLOW} Downloading wdissector.tar.zst to $(pwd)${NC}"
    rm -f wdissector.tar.zst || true
    wget -O wdissector.tar.zst $WDISSECTOR_URL
    echo -e "${GREEN}[2/5]${YELLOW} Extracting wdissector.tar.zst to $(pwd)/wdissector${NC}"
    pv wdissector.tar.zst | tar -I zstd -x
    rm wdissector.tar.zst
    # Fix wdissector linker error
    sudo ln -sfnv /usr/lib/${ARCH}-linux-gnu/libc.a /usr/lib/${ARCH}-linux-gnu/liblibc.a

    echo -e "${GREEN}[3/5]${YELLOW} Installing wdissector requirements...${NC}"
    ./wdissector/requirements.sh
else
    echo "WDissector runtime found"
fi

# Configure wdissector folders
ln -sfnv $(pwd)/wdissector/bin bin
mkdir -p configs
cp $(pwd)/wdissector/configs/global_config.json configs/global_config.json
cp $(pwd)/wdissector/bindings/python/wdissector.py src/wdissector.py

# Configure Python3 runtime
if [[ ! -f "runtime/python/install/bin/python3.8" ]]
then
    if [[ ! -f "wdissector/modules/python/install/python3.8" ]]
    then
        echo -e "${GREEN}[4/5]${YELLOW} Linking WDissector Python3 runtime...${NC}"
        ln -sfnv $(pwd)/wdissector/modules/ runtime
    else
        echo -e "${GREEN}[4/5]${YELLOW} Downloading Python3 runtime...${NC}"
        wget $PYTHON_URL
        mkdir -p runtime
        mv *.zst runtime/
        cd runtime
        tar -I zstd -xf *.zst
        rm *.zst
        cd ../
    fi
    # Install requirements to python3 runtime
    echo -e "${GREEN}[5/5]${YELLOW} Installing Python3 packages${NC}"
    source scripts/python_env.sh
    $PIP install --no-cache-dir -r scripts/requirements.txt

    # Build internal libraries
    sudo apt install -y gcc g++ --no-install-recommends
    cd src/libs/smp_server/ # smp_server
    CC=gcc CXX=g++ make
    cd ../../../

    # Extra requirements to run wdissector python module (GUI)
    sudo apt install -y libgl1 --no-install-recommends

    # Extra requirements to install nRF52840 firmware
    sudo apt install -y 2to3 python3-distutils
    if [ $ARCH == "x86_64" ]
    then
        $PIP install pc-ble-driver-py==0.17.0 || true
    else
        $PIP install pc-ble-driver-py==0.11.4 || true
    fi

else
    echo "Python3 runtime found"
fi

ls -l

echo -e "${GREEN}Done! Run BLE Defender with: ${YELLOW}./run.sh <MAC_address>${NC}"
