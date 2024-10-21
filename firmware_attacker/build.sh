
if ! which platformio > /dev/null; 
then
  echo "platformio cli not found, installing now..."
  python3 -m pip install -U platformio
fi

platformio run && cp .pio/build/adafruit_feather_nrf52840/firmware.hex firmware.hex

