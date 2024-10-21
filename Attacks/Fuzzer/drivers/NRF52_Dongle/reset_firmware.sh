source check_nrfutil.txt

SERIAL_PORT=$(sudo python reset_to_dfu.py)
if [ -z "$SERIAL_PORT" ]; then
  echo -e "\e[31mNo BLE Dongle was detected, make sure the dongle is inserted!"
else
  sudo ./nrfutil dfu usb-serial -p $SERIAL_PORT -r && echo "Firmware restarted"
fi
