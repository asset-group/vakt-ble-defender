#!/usr/bin/env bash

set -eo pipefail

CLANG_VERSION=15
ARCH="$(uname -m)"
KERNEL="$(uname -r)"
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

	source ./scripts/python_env.sh
	python3 -m pip install -r ./scripts/requirements.txt
else
    echo "WDissector runtime found"
fi

# Configure deploy token
if [[ -v CI_DEPLOY_USER ]]
then
    echo "Configuring credentials for CI/CD..."
    git config --global credential.helper store
    echo "https://$CI_DEPLOY_USER:$CI_DEPLOY_PASSWORD@gitlab.com" > ~/.git-credentials
fi

if [ "$1" == "dev" ]
then
	# Make sure that .config is used
	git config --local include.path ../.gitconfig || true
	# Ubuntu dev. requirements
	sudo apt install -y software-properties-common bc gzip curl git wget zstd \
	libc-ares-dev libssl-dev libgoogle-glog-dev libevent-dev libunwind-dev libgflags-dev # folly requirements

	sudo apt install -y flex bison # libpcap build requirements

	# Install clang-15
	if ! which clang-15 > /dev/null;
	then
	    echo "package clang-15 not found, installing now..."
		# Install clang-15 for Ubuntu
		sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y # add missing libgcc-s1 on Ubuntu18.04
		sudo mkdir -p /usr/lib/python3.6/dist-packages/
		sudo ./scripts/install_llvm.sh $CLANG_VERSION
		CLANG_VERSION_FULL=$(clang-$CLANG_VERSION --version | grep -o -i -E "([0-9]+.){2}[0-9]")
	else
	    echo "clang-15 found!"
	fi

	# Todo: auto detect gcc version
	# Install g++-13 auxiliary libraries for clang
	if which gcc-13 > /dev/null;
	then
	export GCC_FOUND=1
	# Install gcc-11 headers and libraries for use with Clang 15
	sudo apt install g++-13 libstdc++-13-dev -y
	fi

	# Install g++-12 auxiliary libraries for clang
	if which gcc-12 > /dev/null;
	then
	export GCC_FOUND=1
	# Install gcc-12 headers and libraries for use with Clang 15
	sudo apt install g++-12 libstdc++-12-dev -y
	fi

	# Install g++-11 auxiliary libraries for clang
	if which gcc-11 > /dev/null;
	then
	export GCC_FOUND=1
	# Install gcc-11 headers and libraries for use with Clang 15
	sudo apt install g++-11 libstdc++-11-dev -y
	fi

	# Install g++-9
	if ! which g++-9 > /dev/null && [ -z $GCC_FOUND ];
	then
	# Install gcc-9 headers and libraries for use with Clang 15
	sudo apt install gcc-9 g++-9 libstdc++-9-dev -y
	fi

	# Fix lldb-15 on ubuntu18.04
	sudo ln -sfv /usr/lib/llvm-$CLANG_VERSION/lib/python3.6/site-packages/lldb /usr/lib/python3.6/dist-packages/lldb || true
	
	# Install dev tools using existing python3 environment
	source ./scripts/python_env.sh
	python3 -m pip install \
	cmake==3.24.1 -U \
	ninja==1.11.1 -U \
	meson==0.53.0

elif [ "$1" == "firmware" ]
then
	echo "TODO"

else
	# Install runtime-only packages
	# TODO wdissector

	# For ubuntu 22.04 and beyond
	if [  $(echo "$(lsb_release -sr) >= 22.04" | bc ) == "1" ]
	then
		# Install missing libssl1.1.1 for ubuntu 22.04 and beyound
		if [ -z "$(dpkg -l | grep libssl1.1)" ]
		then
			if [ $ARCH == "x86_64" ]
			then
	            wget http://launchpadlibrarian.net/367327833/libssl1.1_1.1.0g-2ubuntu4_amd64.deb
	            sudo apt install -y ./libssl1.1_1.1.0g-2ubuntu4_amd64.deb
	            rm libssl1.1_1.1.0g-2ubuntu4_amd64.deb
			else
	            wget http://launchpadlibrarian.net/367327970/libssl1.1_1.1.0g-2ubuntu4_arm64.deb
	            sudo apt install -y ./libssl1.1_1.1.0g-2ubuntu4_arm64.deb
	            rm libssl1.1_1.1.0g-2ubuntu4_arm64.deb
			fi
		fi
	fi
fi
