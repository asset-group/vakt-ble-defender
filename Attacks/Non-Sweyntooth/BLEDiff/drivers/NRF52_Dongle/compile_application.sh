
if ! which platformio > /dev/null; 
then
  echo "platformio cli not found, installing now..."
  pip install -U platformio 
fi

platformio run