# VaktBLE

<p align="center">
  <img src="PortableSetup/docs/logo_animated.gif" alt="animated" width="300" height="auto"/>
</p>

VaktBLE presents an innovative framework that prevents a malicious BLE central device from establishing a direct connection with the intended peripheral. This method serves to guard it against unforeseen attack surfaces that are carried over BLE packets.


VaktBLE introduces a non-compliant firmware patch, using a [nRF52840 DK](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-DK) and a [nRF52840 Dongle](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle) as a benevolent MitM to send/receive raw link layer packets to and from the malicious central over the air. It is necessary to flash the driver firmware to the board before starting the Python 3.8 scripts.

<p align="center">
  <img src="AnchoredSetup/docs/overview.png" alt="overview" width="500" height="auto"/>
</p>

## Evaluation Machine
In order to facilitate testing, you can use our evaluation machine. This machine is pre-configured with all necessary system libraries and Python dependencies for running VaktBLE. We can provide our SSH private key (named artifact.key) upon request.

```bash
chmod 0600 artifact.key
ssh -i artifact.key artifact@evaluation.vaktble.com -p 2222
```

# Getting started

## Installation

Ensure that you have the Python packages mentioned in the `AnchoredSetup/bridge/requirements.sh` file. If you are using Ubuntu, run can run the following commands:

#### A. Intall linux requirements
```bash
git clone https://anonymous-person@github.com/acsac-2024/vakt-ble-defender.git # Use password below
# Password: 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
cd vaktble-ble-defender/AnchoredSetup/bridge/
./requirements.sh 
```

#### B. Flash custom central and peripheral firmware

The binaries of our firmware are separated for the peripheral and the central that composes our MiTM. 

In order to flash the non-compliant peripheral you can run the following commands inside `PortableSetup` folder.

```shell
cd PortableSetup/
sudo chown $USER:$USER /dev/ttyACM0 # Give user permission to serial port
./firmware.sh peripheral flash
./firmware.sh central flash 
```

#### C. Alternative nRF52 driver flashing method

If the previous flashing method didn't work, you can also flash the firmware by using the [nRF Connect App for Desktop](https://www.nordicsemi.com/Products/Development-tools/nrf-connect-for-desktop). This application provides a user-friendly interface for flashing the hexadecimal firmware.

## 2) Usage Instructions

To start VaktaBLE you can run the following command:

```bash
cd AnchoredSetup/bridge/
./run.sh c8:c9:a3:d3:65:1e #peripheral address to protect 
```

The output of the script is as follows:

<p align="center">
  <img src="AnchoredSetup/docs/demo_vaktble.png" alt="demo" width="600" height="auto"/>
</p>


## Test attacker exploits

In order to launch an attack you can attach a nRF52840 Dongle and flash it as a central deivce. You need to install nrfutil tool to flash the firmware on the board. Remember to put the nRF52840 on DFU mode before flashing (reset the USB dongle while it is connected to your PC by pressing the small reset button),then you can run the following commands:

```bash
cd firmware_attacker
python3 -m pip install nrfutil pyserial pycryptodome six
nrfutil dfu usb-serial -p COM_PORT -pkg nRF52_driver_firmware.zip
```

The scripts are functional on both Linux and Windows. All that's required is to modify the COM_PORT parameter to correspond with the nRF52840 port name. You can use `dmesg -w` to verify the port.

#### Running the attacks 

After the requirements have been installed, you can initiate an exploit script by running the subsequent command under `/bridge/exploits` folder:

```bash
cd Attacks/Sweyntooth
source venv/bin/activate
./link_layer_length_overflow.py c8:c9:a3:d3:65:1e
```

For instance when launching simultaniously VaktBLE and one attack (i.e., KNOB Tester Bluetooth Low Energy variant), the output is as follows. 

VaktaBLE malformed detection example:


<p align="center">
  <img src="AnchoredSetup/docs/knob_demo_vaktble.png" alt="knobdemo" width="600" height="auto"/>
</p>

The attacker output:
<p align="center">
  <img src="AnchoredSetup/docs/knob_attack_demo.png" alt="knobattack" width="600" height="auto"/>
</p>

Knob attacks send a key size of 17 in the pairing request (SM_Pairing_Request), which is outside the scope of BLE specifications. As a result, VaktBLE promptly blocks such exploitation attempts by refusing to forward BLE packets from the malicious central to the legitimate peripheral. Additionally, it highlights the issue by identifying the specific BLE packet (e.g., `[Malformed]` `SM_Pairing_Request`). We can note that after the malformed packet was sent, VaktBLE drops the connection, thus, the attacker starts to send advertisements packets (i.e., `BTLE_SCAN_REQ`).


# Full Documentation

For more information on VaktBLE, please read our artifact PDF, which includes a detailed description on how to run the experiments performed in VaktBLE paper: [./AnchoredSetup/docs/vaktble_documentation.pdf](AnchoredSetup/docs/vaktble_documentation.pdf)
