#!/usr/bin/env ./runtime/python/install/bin/python3

import sys
import os
import subprocess
import shutil
import platform
from time import sleep
from pathlib import Path
from hashlib import sha1
from urllib.request import urlretrieve
from zipfile import ZipFile, ZIP_DEFLATED
import time

USB_VALID_PORTS_DESC = [
    'BLEDefender Central',
]

USB_VALID_PORTS_BOOTLOADER_DESC = [
    'Open DFU Bootloader',
    'PCA10056 - nRF Serial'
]

args = sys.argv[1:]
system_name = platform.system()
is_linux = system_name == 'Linux' or system_name == 'Darwin'
script_path = sys.path[0]
pio_build_path = Path('.pio/build/central_nrf52840/')
firmware_path = pio_build_path / 'firmware.hex'
pio_bin_path = Path.home() / '.platformio/penv/bin/'
python_bin_folder = Path(sys.executable).parent
os.environ["PATH"] = str(python_bin_folder) + ':' + os.environ["PATH"]
os.environ["PATH"] = str(pio_bin_path) + ':' + os.environ["PATH"]

# Import some libs
try:
    import serial
    import serial.tools.list_ports
except:
    print("[ERROR] pyserial module not found, installing now via pip...")
    os.system(sys.executable + ' -m pip install pyserial --upgrade')
    os.sync()


try:
    import nordicsemi
except:
    print("[ERROR] nrfutil module or requirements not found, installing now via pip...")
    os.system(sys.executable + ' -m pip install nrfutil --upgrade')
    os.sync()


def has_program(prg_name):
    if is_linux:
        find_cmd = 'which'
    else:
        find_cmd = 'where'

    result = subprocess.run(
        [find_cmd, prg_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    if len(output) > 0 and result.returncode == 0:
        return output
    return None


def is_source_project():
    return os.path.isdir('src')


def get_platformio_version():
    result = subprocess.run(
        ['pio', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    return result.split(b' ')[-1].replace(b'\r', b'').replace(b'\n', b'')


def get_platformio_config_json():
    return subprocess.run(['pio', 'project', 'config', '--json-output'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.replace(b'\r', b'').replace(b'\n', b'')


def generate_project_checksum():
    print('Generating project.checksum')
    # PIO Core version changes
    checksum = sha1(get_platformio_version())
    # Configuration file state
    checksum.update(get_platformio_config_json())
    # Write project checksum
    with open(Path('.pio/build/project.checksum'), 'w') as out:
        out.write(checksum.hexdigest())


def download_file(url, file_name):
    if os.path.isfile(file_name):
        return

    def ProgressBar(block_num, block_size, total_size):
        downloaded = block_num * block_size
        if downloaded < total_size:
            completed = round((downloaded * 100) / total_size, 2)
            sys.stdout.write('\r' + str(completed) + '%')
            sys.stdout.flush()
        else:
            print('\nDone')

    print('Downloading ' + file_name + '...')
    urlretrieve(url, file_name, reporthook=ProgressBar)


def detect_serial_port():

    ports = serial.tools.list_ports.comports()
    for port in ports:
        if (USB_VALID_PORTS_DESC[0] in port.description) or (port.description in USB_VALID_PORTS_BOOTLOADER_DESC):
            return port.device


def is_dfu_port(serial_port):
    ports = serial.tools.list_ports.comports()
    for port in ports:
        if port.description in USB_VALID_PORTS_BOOTLOADER_DESC:
            return True

    return False


def reset_to_dfu(serial_port):
    ser = serial.Serial(serial_port, 38400, rtscts=1)
    ser.write(b'\xA6\xC7')
    ser.close()
    print('Reset to DFU done!')


def flash_firmware(serial_port, application_only=False):
    os.makedirs(pio_build_path, exist_ok=True)

    if not is_source_project():
        generate_project_checksum()
        os.system('mkdir -p binaries')
        shutil.copyfile('binaries/firmware.hex',
                        pio_build_path / 'firmware.hex')
    elif not os.path.isfile(pio_build_path / 'firmware.hex'):
        print('[ERROR] Build project first. Example: ./firmware.py build')
        exit(1)

    print('Building DFU Package...')

    # For Nordic Bootloader (nRF52840 Dongle)
    # if not application_only:
    # os.system(sys.executable + ' nordicsemi/nrfutil pkg generate --hw-version 52 --debug-mode \
    #     --sd-req 0x00 --sd-id 0xB6 \
    #     --softdevice binaries/s140_nrf52_6.1.1_softdevice.hex \
    #     --application %s binaries/app_dfu_package.zip' % (firmware_path))
    # else:
    os.system(sys.executable + " nordicsemi/nrfutil pkg generate --hw-version 52 --application-version 1 \
        --application %s \
        --sd-req 0xB6 binaries/app_dfu_package.zip" % (firmware_path))

    # For Adafruit Bootloader (nRF52840 DK) (Writing softdevice does not work)
    # if not application_only:
    #     os.system('adafruit-nrfutil dfu genpkg --dev-type 82 \
    #         --softdevice binaries/s140_nrf52_6.1.1_softdevice.hex \
    #         --sd-req 0x00 \
    #         --application %s \
    #         binaries/app_dfu_package.zip' % (firmware_path))
    # else:
    # os.system('adafruit-nrfutil dfu genpkg --dev-type 82 --application-version 1 \
    #     --application %s \
    #     --sd-req 0xB6 \
    #     binaries/app_dfu_package.zip' % (firmware_path))

    if not is_dfu_port(serial_port):
        reset_to_dfu(serial_port)

    print('Waiting DFU boot time')
    time.sleep(0.5)
    print('Flashing Firmware...')
    os.system(sys.executable + ' nordicsemi/nrfutil dfu usb-serial -p %s -pkg binaries/app_dfu_package.zip --connect-delay=1' % (serial_port))
    # os.system('adafruit-nrfutil --verbose dfu serial --package binaries/app_dfu_package.zip -p %s --singlebank -fc' % (serial_port))


if __name__ == "__main__":
    # Change working dir to script path
    os.chdir(script_path)
    enable_build = is_source_project()
    home_path = str(Path.home())

    if is_linux:
        # Fix locale
        os.environ['LC_ALL'] = 'C.UTF-8'
        os.environ['LANG'] = 'C.UTF-8'

    # Check for pio and install if necessary
    if not has_program('pio'):
        # Try adding platformio bin folder to path environment
        if is_linux:
            os.environ['PATH'] = home_path + \
                '/.platformio/penv/bin/:' + os.environ['PATH']
        elif platform.system() == 'Windows':
            os.environ['Path'] = home_path + \
                '\\.platformio\\penv\\Scripts;' + os.environ['Path']
        # install platformio if not present on system
        if not has_program('pio'):
            print('Platformio not found, installing now...')
            os.system('mkdir -p scripts')
            download_file(
                'https://raw.githubusercontent.com/platformio/platformio-core-installer/master/get-platformio.py',
                'scripts/get-platformio.py')
            os.system(sys.executable + ' scripts/get-platformio.py')

    # Handle arguments
    if len(args):

        for i, arg in enumerate(args):
            if 'build' in arg and enable_build:
                print('Building firmware from source...')
                os.system('pio run')
                os.system('mkdir -p binaries')
                shutil.copyfile(pio_build_path / 'firmware.hex',
                                Path('binaries/firmware.hex'))
                os.makedirs('release/binaries', exist_ok=True)
                shutil.copyfile('binaries/firmware.hex',
                                Path('release/binaries/firmware.hex'))
                shutil.copyfile('./../scripts/vaktble_bootloader-0.7.0-32-g7210c39-dirty_s140_6.1.1.hex',
                                Path('release/binaries/vaktble_bootloader-0.7.0-32-g7210c39-dirty_s140_6.1.1.hex'))
                shutil.copyfile('platformio.ini', Path(
                    'release/platformio.ini'))
                shutil.copyfile('firmware.py', Path('release/firmware.py'))
                shutil.rmtree(Path('release/nordicsemi'), ignore_errors=True)
                shutil.copytree('nordicsemi', Path('release/nordicsemi'))
                # Create a ZipFile Object
                with ZipFile(Path('release/vaktble_firmware_central.zip'), 'w', ZIP_DEFLATED) as zipObj:
                    # Add multiple files to the zip
                    zipObj.write(Path('release/binaries/firmware.hex'))
                    zipObj.write(
                        Path('release/binaries/vaktble_bootloader-0.7.0-32-g7210c39-dirty_s140_6.1.1.hex'))
                    zipObj.write(Path('release/platformio.ini'))
                    zipObj.write(Path('release/firmware.py'))
                    nordicsemi_module = Path('release/nordicsemi').resolve()
                    for root, dirs, files in os.walk(nordicsemi_module):
                        for file in files:
                            if '.pyc' in file:
                                continue
                            zipObj.write(root + os.sep + file,
                                         os.path.relpath(root + os.sep + file))
                exit(0)

            elif 'clean' == arg and enable_build:
                os.system('pio run -v -t clean')

            elif 'flash' == arg:
                application_only = False

                if (i + 1) < len(args):
                    serial_port = args[i + 1]
                else:
                    serial_port = detect_serial_port()

                if serial_port:
                    print("[INFO] Detected Serial Port: " + serial_port)
                    flash_firmware(serial_port)
                else:
                    print('[INFO] No serial ports detected')

                exit(0)

            elif 'flash_app' == arg:

                if (i + 1) < len(args):
                    serial_port = args[i + 1]
                else:
                    serial_port = detect_serial_port()

                if serial_port:
                    print("[INFO] Detected Serial Port: " + serial_port)
                    flash_firmware(serial_port, True)
                else:
                    print('[INFO] No serial ports detected')

                exit(0)

            elif 'reset' == arg:
                if (i + 1) < len(args):
                    serial_port = args[i + 1]
                else:
                    serial_port = detect_serial_port()

                print("[INFO] Detected Serial Port: " + serial_port)
                reset_to_dfu(serial_port)
                exit(0)

    # Print usage
    print('------ Usage help -------')
    if enable_build:
        print('./firmware.py build                  # Build firmware using platformio and distribute it to release folder')
        print('./firmware.py clean                  # Clean firmware build files')
    print('./firmware.py flash     <port name>  # Flash firmware using serial port')
    print('./firmware.py flash_app <port name>  # Flash only FW application using serial port (faster)')
    print('./firmware.py reset     <port name>  # Reset firmware using serial port')
