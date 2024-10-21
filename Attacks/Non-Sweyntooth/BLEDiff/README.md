# BLE-PoC

Proof of Concept for BLE attacks

## Setup Environment

```bash
sudo chmod +x ./setup.sh
sudo ./setup.sh
cd bluetooth/smp_server/
/usr/bin/python2.7 setup.py build
sudo /usr/bin/python2.7 setup.py install
mkdir -p ~/.local/lib/python2.7/site-packages/
cp dist/BLESMPServer-1.0.1-py2.7-linux-x86_64.egg ~/.local/lib/python2.7/site-packages
cd ../../
```

## Setup nRF52480

- Install nRF Connect for Desktop from [Nordic website](https://www.nordicsemi.com/Products/Development-tools/nrf-connect-for-desktop)
- You will need to write the provided hex files to the nRF5280 dongle. You can do this on windows or ubuntu. Windows is more preferable.
- To do this on ubuntu, run the nRF connect in sudo mode and add --no-sandbox flag
- Run the Programmer app from nRF connect
- Connect nRF52480 in DFU mode and write the two files from `nRF52480_hex_files/`
- After writing the hex files, remove the device from workstation and reconnect it.
- To test the Android device, you will need to install the nRF Connect for Mobile app on your device. 
- The device has been tested on Huawei Y5 2018, in case you test on another phone you will need to modify the `adb shell input tap X Y` lines to simulate the expected X Y values.

## Run PoC

- Change "SlaveAddress" and "SlaveAddressType" at `addr_config.json` file. 
- Run the following command to test issue 1: `sudo /usr/bin/python2.7 ./bypassing_legacy_pairing.py`
- Run the following command to test issue 2: `sudo /usr/bin/python2.7 ./unresponsive_with_pause_enc_resp_plain`
