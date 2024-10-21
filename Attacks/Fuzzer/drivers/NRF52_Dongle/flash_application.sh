source check_nrfutil.txt

mkdir -p .pio/build/adafruit_feather_nrf52840/
FIRMWARE_PATH=$(ls .pio/build/adafruit_feather_nrf52840/firmware.hex)

if [ -z $FIRMWARE_PATH ]
then
	FIRMWARE_PATH="firmware.hex"
fi

echo "Flashing $FIRMWARE_PATH"

./nrfutil pkg generate --hw-version 52 --application-version 1 --application $FIRMWARE_PATH --sd-req 0xB6 app_dfu_package.zip
./flash.sh
