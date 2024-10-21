import time
import threading
import sys
import logging
import threading

from colorama import Fore, Back, Style
import serial
from serial.tools.list_ports import comports
from serial.threaded import ReaderThread, LineReader
from logbook import Logger, RotatingFileHandler

import greyhound.fitness as fitness

LOG_PATH = 'logs/monitor_serial/'


class Monitor:
    ser = None
    ser_name = None
    magic_string = None
    magic_string_ignore = None
    log_file = None
    user_callback = None

    logger_enabled = False
    logger = None
    logger_filehandler = None
    stop_request = False

    def __init__(self, serial_port, baudrate, parity=serial.PARITY_NONE, magic_string=None,
                 user_callback=None,
                 logger_enabled=True,
                 magic_string_ignore=None):

        if magic_string is not None:
            self.magic_string = magic_string

        if magic_string_ignore is not None:
            self.magic_string_ignore = magic_string_ignore

        if user_callback is not None:
            self.user_callback = user_callback

        if '*' in serial_port:
            port_name = serial_port.split('*')[0]
            available_ports = [str(x.device) for x in comports()]
            found = False
            for idx, port in enumerate(available_ports):
                if port_name in port:
                    serial_port = port
                    found = True

            if not found:
                print(Fore.RED + 'Serial port ' + serial_port + ' not found!')
                return
        try:
            self.ser = serial.Serial(serial_port, baudrate, parity=parity, timeout=0.5)
        except:
            print(Fore.RED + 'Serial port ' + serial_port + " can't be opened!")
            return
        print(Fore.CYAN + 'Serial port ' + Fore.YELLOW + serial_port + Fore.CYAN +
              ' opened with baudrate ' + Fore.YELLOW + str(baudrate))

        self.ser_name = serial_port.split('/')[-1]

        if logger_enabled:
            self.start_log(self.get_log_name())
            self.logger.info("Logger started")
            self.logger_enabled = True

        thread = threading.Thread(target=self.serial_receiving_loop)
        thread.daemon = True
        thread.start()

    def serial_receiving_loop(self):
        while self.stop_request is False:
            try:
                while self.stop_request is False:
                    string = self.ser.readline()
                    if len(string) and self.logger_enabled:
                        string = string.replace('\n', '')
                        self.logger.info(string)

                    if self.magic_string and self.magic_string in string:
                        if self.user_callback is not None:
                            self.user_callback()
                            self.stop_log()
                            self.start_log(self.get_log_name())
            except:
                time.sleep(1)

    def get_log_name(self):
        return 'logs/' + fitness.model_name + \
               '/monitor_serial/' + self.ser_name + '-' \
               + str(time.time()) + '.txt'

    def register_magic_string(self, string):
        self.magic_string = string

    def start_log(self, filename):
        handler = RotatingFileHandler(filename, mode='a', max_size=1048576,
                                      format_string=u'[{record.time:%Y-%m-%d %H:%M:%S.%f%z}] {record.message}')
        handler.push_application()
        log = Logger('monitor_serial')

        self.logger = log
        self.logger_filehandler = handler

    def stop_log(self):
        self.logger_filehandler.close()
        self.logger_filehandler.pop_application()
        del self.logger_filehandler
