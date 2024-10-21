source check_nrfutil.txt

FIRMWARE_PATH=$(ls .pio/build/adafruit_feather_nrf52840/firmware.hex)

if [ -z $FIRMWARE_PATH ]
then
	FIRMWARE_PATH="firmware.hex"
fi

echo "Flashing $FIRMWARE_PATH and Soft Device"

nrfutil pkg generate --hw-version 52 --debug-mode --sd-req 0x00 --sd-id 0xB6 --application $FIRMWARE_PATH --softdevice s140_nrf52_6.1.1_softdevice.hex app_dfu_package.zip

./flash.sh