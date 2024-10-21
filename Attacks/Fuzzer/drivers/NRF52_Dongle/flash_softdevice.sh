source check_nrfutil.txt

./nrfutil pkg generate --hw-version 52 --debug-mode --sd-req 0x00 --sd-id 0xB6 --softdevice s140_nrf52_6.1.1_softdevice.hex app_dfu_package.zip
./flash.sh