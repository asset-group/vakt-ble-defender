source check_nrfutil.txt

SERIAL_PORT=$(sudo python reset_to_dfu.py)
if [ -z "$SERIAL_PORT" ]; then
  echo -e "\e[31mNo BLE Dongle was detected, make sure the dongle is inserted!"
else
  echo "Flashing $SERIAL_PORT using nrfutil..."
  sudo ./nrfutil dfu usb-serial -p $SERIAL_PORT -pkg app_dfu_package.zip
  echo "Flash completed on $SERIAL_PORT"
fi
