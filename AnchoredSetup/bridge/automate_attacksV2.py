#!/usr/bin/env python3
import subprocess, sys, os, time, random, signal
from time import sleep
import serial.tools.list_ports
from colorama import Fore
from serial.tools import list_ports
from src.uhubctl_cycle import device_cycle_port

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


#os.environ['CONTINUE_ATTACK'] = "0"
exploits_folder = '../../Attacks/Sweyntooth'
ble_defender = './run.sh'
target_address = 'C8:C9:A3:D3:65:1E'

def run_command_in_new_terminal(command, cwd=None):
    terminal_command = "sudo gnome-terminal -- bash -c '{0}; exec bash'".format(command)
    process = subprocess.Popen(terminal_command, shell=True, cwd=cwd, preexec_fn=os.setsid)
    return process

def run_command(command, cwd=None):
    process = subprocess.Popen(command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process

def wait_for_process(process, timeout=20):
    start_time = time()
    while time.time() - start_time < timeout:
        if process.poll() is not None:
            return True
        sleep(1)
    return False

def terminate_process(process):
    if process and process.poll() is None:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)

def main():
    attacker_serial_port = discover_attacker_dongle()
    print(Fore.YELLOW + 'Advertiser Address: ' + target_address.upper())

    # Launch BLE defender once
    ble_defender_command = "{0} {1}".format(ble_defender, target_address)
    ble_defender_process = run_command_in_new_terminal(ble_defender_command, cwd=os.path.dirname(ble_defender))
    print(Fore.CYAN + "\t-------------BLE-defender Launched--------------")
    
    sleep(7)  # Give some time for BLE-defender to initialize

    # Launch a single terminal for attacks
    #attack_terminal_command = "bash"
    #attack_terminal = run_command_in_new_terminal(attack_terminal_command, cwd=exploits_folder)
    print(Fore.CYAN + "\t-------------Attack Terminal Launched--------------")

    try:
        while True:
            device_cycle_port('Silicon Labs', cfg_file_name='uhubctl_automate.json')
            files = [f for f in os.listdir(exploits_folder) if f.endswith('.py') and 'discover.py' not in f]
            exploit_file = random.choice(files)
            print(Fore.CYAN + "\t------Attack in this iteration: {0}{1}{2}".format(Fore.LIGHTYELLOW_EX, exploit_file, Fore.CYAN))
            
            attack_command = "timeout --preserve-status -k 12 10 ./{0} {1}".format(exploit_file, target_address)
            
            # Use subprocess.call to run the attack command in the current process
            print(Fore.RED + "\t-------------Launching Attack--------------")
            return_code = subprocess.call(attack_command, shell=True, cwd=exploits_folder)
            
            if return_code != 0:
                print(Fore.RED + "Attack process exited with non-zero status: {}".format(return_code))
            
            print(Fore.GREEN + "\t-------------Attack Completed--------------")
            print(Fore.GREEN + "\t-------------Restarting Target for stability--------------")

            sleep(2)
            #user_input = input(Fore.YELLOW + "Do you want to continue with another attack? (y/n): ")
            #if user_input.lower() != 'y':
            #    break

        print(Fore.GREEN + "Attack sequence completed.")
    finally:
        # Terminate BLE defender process
        terminate_process(ble_defender_process)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nProgram interrupted by user. Cleaning up...")
    #finally:
    #    print(Fore.GREEN + "\n Cleanup completed. Exiting.\n\n")