#!/usr/bin/python3
import subprocess, sys, os, random, time
import serial.tools.list_ports
from colorama import Fore
from serial.tools import list_ports

exploits_folder = '../../Attacks/Sweyntooth'
ble_defender = './run.sh'  # Changed to relative path
advertiser_address = 'C8:C9:A3:D3:65:1E'

def discover_attacker_dongle(dev_idx=0):
    ports = list_ports.comports()
    # Sort ports list
    ports.sort(key=lambda x: x.device)

    dev_peripheral = None
    idx_peripheral = 0

    for port in ports:
        # print(port.device + ' : ' + port.description)
        if 'Attacker Dongle' in port.description:
            print('Found' + str(port.description) + 'in ' + str(port.device))
            if idx_peripheral >= dev_idx:
                dev_peripheral = port.device
            idx_peripheral += 1

    return [dev_peripheral, idx_peripheral - 1]

os.environ['CONTINUE_ATTACK'] = "1"


def launch_attack(exploit_file, dongle):
    print(Fore.CYAN + f"\t------Attack in this iteration: {Fore.LIGHTYELLOW_EX}{exploit_file}{Fore.CYAN}")
    try:
        # Changed the way ble_defender is launched
        ble_defender_process = subprocess.Popen([ble_defender, advertiser_address], cwd=os.path.dirname(ble_defender))
        print(Fore.CYAN + "\t-------------BLE-defender Launched--------------")
        time.sleep(5)
        
        attack_command = f"sudo ./{exploit_file} {dongle} {advertiser_address}"
        launch_attack = subprocess.Popen(attack_command, cwd=exploits_folder, shell=True)
        print(Fore.RED + "\t-------------Attack Launched--------------")
        
        try:
            stdout_exploit, stderr = launch_attack.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            print(Fore.RED + "Attacker missed the connection")
        finally:
            ble_defender_process.terminate()
            launch_attack.terminate()
        
        return True
    
    except KeyboardInterrupt:
        print(Fore.YELLOW + "Attack interrupted by user.")
        return False

def main():
    attacker_serial_port = discover_attacker_dongle()

    print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())
    while True:
        files = [f for f in os.listdir(exploits_folder) if f.endswith('.py')]
        exploit_file = random.choice(files)
        
        continue_attacks = launch_attack(exploit_file, attacker_serial_port[0].upper())
        if not continue_attacks:
            break
    
    print(Fore.GREEN + "Attack sequence completed.")

if __name__ == "__main__":
    try:

        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nProgram interrupted by user. Cleaning up...")
    finally:
        #subprocess.call(["sudo", "fuser", "-k", "/dev/ttyACM*"])
        subprocess.call(['sudo', 'uhubctl', '-l', '1-1', '-p', '3', '-a', 'cycle', '-d', '0.1'])
        subprocess.call(['sudo', 'uhubctl', '-l', '1-2', '-p', '1', '-a', 'cycle', '-d', '0.1'])


        print(Fore.GREEN + "\n Cleanup completed. Exiting.\n\n")