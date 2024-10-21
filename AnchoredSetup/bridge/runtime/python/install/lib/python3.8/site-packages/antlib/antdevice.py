# Copyright 2019 Garmin Canada, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


'''
Wraps the c api for ANT_WrappedLib.dll
'''

#pylint: disable=too-many-lines

#Python imports
import collections
import ctypes as ct
from os import path
import struct
import sys
import warnings

#Module imports
import antlib.antdefines as antdefs
import antlib.antmessage as msg

def _load_ant_lib():
    '''
    Find and load the ant c library.
    '''
    #pylint: disable=too-many-statements
    #pylint: disable=line-too-long

    # So that we don't need the ct prefix everywhere.
    from ctypes import (POINTER, c_bool, c_ubyte, c_ushort, c_ulong, c_int,
                        c_void_p, c_char_p, CDLL)

    def _load_lib(name):
        dll = path.realpath(path.join(path.dirname(__file__), name))

        try:
            return CDLL(dll)
        except Exception as err:
            raise RuntimeError('Unable to load {}'.format(dll), err)

    # #Below section commented out for future use when the
    # linux and mac libs are available.
    # if sys.platform == "linux" or sys.platform == "linux2":
    #     lib = _load_lib('linux/ANT_Unmanaged_Wrapper.so')
    # elif sys.platform == "darwin":
    #     lib = _load_lib('darwin/ANT_Unmanaged_Wrapper.dylib')

    if sys.platform == "win32":
        if struct.calcsize("P") * 8 == 32:
            lib = _load_lib('win32/ANT_WrappedLib.dll')
            # Workaround to correctly add the DLLs to the path so they initialize correctly
            _load_lib('win32/DSI_SiUSBXp_3_1.dll')
            _load_lib('win32/DSI_CP210xManufacturing_3_1.dll')
        else:
            lib = _load_lib('win64/ANT_WrappedLib.dll')
            warnings.warn("Using 64bit package does not support communications with UIF boards.")
    else:
        raise RuntimeError('Platform "{}" is unsupported'.format(sys.platform))

    #Defining return and argument types for the unmanaged wrapper functions

    lib.getUnmanagedVersion.argtypes = None
    lib.getUnmanagedVersion.restype = c_char_p
    if sys.platform == "linux" or sys.platform == "linux2":
        lib.ANT_Init_UART.argtypes = [POINTER(c_ubyte), c_ulong, POINTER(c_void_p), POINTER(c_void_p), c_ubyte]
        lib.ANT_Init_UART.restype = c_int
    lib.ANT_Init.argtypes = [c_ubyte, c_ulong, POINTER(c_void_p), POINTER(c_void_p), c_ubyte, c_ubyte]
    lib.ANT_Init.restype = c_int
    lib.ANT_Close.argtypes = [c_void_p, c_void_p]
    lib.ANT_Close.restype = None
    if sys.platform != "linux" and sys.platform != "linux2":
        lib.ANT_USBReset.argtypes = [c_void_p]
        lib.ANT_USBReset.restype = c_bool
    lib.ANT_ResetSystem.argtypes = [c_void_p, c_ulong]
    lib.ANT_ResetSystem.restype = c_bool
    lib.ANT_SetNetworkKey_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_SetNetworkKey_RTO.restype = c_bool
    lib.ANT_AssignChannel_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_AssignChannel_RTO.restype = c_bool
    lib.ANT_AssignChannelExt_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_AssignChannelExt_RTO.restype = c_bool
    lib.ANT_UnAssignChannel_RTO.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_UnAssignChannel_RTO.restype = c_bool
    lib.ANT_SetChannelId_RTO.argtypes = [c_void_p, c_ubyte, c_ushort, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetChannelId_RTO.restype = c_bool
    lib.ANT_SetChannelPeriod_RTO.argtypes = [c_void_p, c_ubyte, c_ushort, c_ulong]
    lib.ANT_SetChannelPeriod_RTO.restype = c_bool
    lib.ANT_RSSI_SetSearchThreshold_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_RSSI_SetSearchThreshold_RTO.restype = c_bool
    lib.ANT_SetLowPriorityChannelSearchTimeout_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetLowPriorityChannelSearchTimeout_RTO.restype = c_bool
    lib.ANT_SetChannelSearchTimeout_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetChannelSearchTimeout_RTO.restype = c_bool
    lib.ANT_SetChannelRFFreq_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetChannelRFFreq_RTO.restype = c_bool
    lib.ANT_SetTransmitPower_RTO.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_SetTransmitPower_RTO.restype = c_bool
    lib.ANT_SetChannelTxPower_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetChannelTxPower_RTO.restype = c_bool
    lib.ANT_ConfigureSplitAdvancedBursts.argtypes = [c_void_p, c_bool]
    lib.ANT_ConfigureSplitAdvancedBursts.restype = c_bool
    lib.ANT_ConfigureAdvancedBurst_RTO.argtypes = [c_void_p, c_bool, c_ubyte, c_ulong, c_ulong, c_ulong]
    lib.ANT_ConfigureAdvancedBurst_RTO.restype = c_bool
    lib.ANT_ConfigureAdvancedBurst_ext_RTO.argtypes = [c_void_p, c_bool, c_ubyte, c_ulong, c_ulong, c_ushort, c_ubyte, c_ulong]
    lib.ANT_ConfigureAdvancedBurst_ext_RTO.restype = c_bool
    lib.ANT_RequestMessage.argtypes = [c_void_p, c_ubyte, c_ubyte, POINTER(msg.MarshallAntMessageItem), c_ulong]
    lib.ANT_RequestMessage.restype = c_bool
    lib.ANT_RequestUserNvmMessage.argtypes = [c_void_p, c_ubyte, c_ubyte, POINTER(msg.MarshallAntMessageItem), c_ushort, c_ubyte, c_ulong]
    lib.ANT_RequestUserNvmMessage.restype = c_bool
    lib.ANT_OpenChannel_RTO.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_OpenChannel_RTO.restype = c_bool
    lib.ANT_CloseChannel_RTO.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_CloseChannel_RTO.restype = c_bool
    lib.ANT_SendBroadcastData.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte)]
    lib.ANT_SendBroadcastData.restype = c_bool
    lib.ANT_SendAcknowledgedData_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_SendAcknowledgedData_RTO.restype = c_ubyte
    lib.ANT_SendBurstTransfer_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong, c_ulong]
    lib.ANT_SendBurstTransfer_RTO.restype = c_ubyte
    lib.ANT_SendAdvancedBurstTransfer_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong, c_ubyte, c_ulong]
    lib.ANT_SendAdvancedBurstTransfer_RTO.restype = c_ubyte
    lib.ANT_SendExtBroadcastData.argtypes = [c_void_p, c_ubyte, c_ushort, c_ubyte, c_ubyte, POINTER(c_ubyte)]
    lib.ANT_SendExtBroadcastData.restype = c_bool
    lib.ANT_SendExtAcknowledgedData_RTO.argtypes = [c_void_p, c_ubyte, c_ushort, c_ubyte, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_SendExtAcknowledgedData_RTO.restype = c_ubyte
    lib.ANT_SendExtBurstTransfer_RTO.argtypes = [c_void_p, c_ubyte, c_ushort, c_ubyte, c_ubyte, POINTER(c_ubyte), c_ulong, c_ulong]
    lib.ANT_SendExtBurstTransfer_RTO.restype = c_ubyte
    lib.ANT_InitCWTestMode_RTO.argtypes = [c_void_p, c_ulong]
    lib.ANT_InitCWTestMode_RTO.restype = c_bool
    lib.ANT_SetCWTestMode_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetCWTestMode_RTO.restype = c_bool
    lib.ANT_AddChannelID_RTO.argtypes = [c_void_p, c_ubyte, c_ushort, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_AddChannelID_RTO.restype = c_bool
    lib.ANT_ConfigList_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_ConfigList_RTO.restype = c_bool
    lib.ANT_OpenRxScanMode_RTO.argtypes = [c_void_p, c_ulong]
    lib.ANT_OpenRxScanMode_RTO.restype = c_bool
    lib.ANT_Script_Write_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_Script_Write_RTO.restype = c_bool
    lib.ANT_Script_Clear_RTO.argtypes = [c_void_p, c_ulong]
    lib.ANT_Script_Clear_RTO.restype = c_bool
    lib.ANT_Script_SetDefaultSector_RTO.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_Script_SetDefaultSector_RTO.restype = c_bool
    lib.ANT_Script_EndSector_RTO.argtypes = [c_void_p, c_ulong]
    lib.ANT_Script_EndSector_RTO.restype = c_bool
    lib.ANT_Script_Dump_RTO.argtypes = [c_void_p, c_ulong]
    lib.ANT_Script_Dump_RTO.restype = c_bool
    lib.ANT_Script_Lock_RTO.argtypes = [c_void_p, c_ulong]
    lib.ANT_Script_Lock_RTO.restype = c_bool
    lib.ANT_RxExtMesgsEnable_RTO.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_RxExtMesgsEnable_RTO.restype = c_bool
    lib.ANT_SetSerialNumChannelId_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetSerialNumChannelId_RTO.restype = c_bool
    lib.ANT_EnableLED_RTO.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_EnableLED_RTO.restype = c_bool
    lib.ANT_GetDeviceUSBPID.argtypes = [c_void_p, POINTER(c_ushort)]
    lib.ANT_GetDeviceUSBPID.restype = c_bool
    lib.ANT_GetDeviceUSBVID.argtypes = [c_void_p, POINTER(c_ushort)]
    lib.ANT_GetDeviceUSBVID.restype = c_bool
    if sys.platform != "linux" and sys.platform != "linux2":
        lib.ANT_GetDeviceUSBInfo.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte)]
        lib.ANT_GetDeviceUSBInfo.restype = c_bool
        lib.ANT_GetDeviceSerialString.argtypes = [c_void_p, POINTER(c_ubyte)]
        lib.ANT_GetDeviceSerialString.restype = c_bool
    lib.ANT_GetDeviceSerialNumber.argtypes = [c_void_p]
    lib.ANT_GetDeviceSerialNumber.restype = c_ulong
    if sys.platform != "linux" and sys.platform != "linux2":
        lib.ANT_GetNumDevices.argtypes = None
        lib.ANT_GetNumDevices.restype = c_ulong
    lib.ANT_CrystalEnable.argtypes = [c_void_p, c_ulong]
    lib.ANT_CrystalEnable.restype = c_bool
    lib.ANT_SetLibConfig.argtypes = [c_void_p, c_ubyte, c_ulong]
    lib.ANT_SetLibConfig.restype = c_bool
    lib.ANT_SetProximitySearch.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetProximitySearch.restype = c_bool
    lib.ANT_ConfigFrequencyAgility.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_ConfigFrequencyAgility.restype = c_bool
    lib.ANT_ConfigEventBuffer.argtypes = [c_void_p, c_ubyte, c_ushort, c_ushort, c_ulong]
    lib.ANT_ConfigEventBuffer.restype = c_bool
    lib.ANT_ConfigEventFilter.argtypes = [c_void_p, c_ushort, c_ulong]
    lib.ANT_ConfigEventFilter.restype = c_bool
    lib.ANT_ConfigHighDutySearch.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_ConfigHighDutySearch.restype = c_bool
    lib.ANT_ConfigSelectiveDataUpdate.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_ConfigSelectiveDataUpdate.restype = c_bool
    lib.ANT_SetSelectiveDataUpdateMask.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_SetSelectiveDataUpdateMask.restype = c_bool
    lib.ANT_ConfigUserNVM.argtypes = [c_void_p, c_ushort, POINTER(c_ubyte), c_ubyte, c_ulong]
    lib.ANT_ConfigUserNVM.restype = c_bool
    lib.ANT_SetChannelSearchPriority.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetChannelSearchPriority.restype = c_bool
    lib.ANT_SetSearchSharingCycles.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_SetSearchSharingCycles.restype = c_bool
    lib.ANT_EncryptedChannelEnable_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_EncryptedChannelEnable_RTO.restype = c_bool
    lib.ANT_AddCryptoID_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ubyte, c_ulong]
    lib.ANT_AddCryptoID_RTO.restype = c_bool
    lib.ANT_ConfigCryptoList_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_ConfigCryptoList_RTO.restype = c_bool
    lib.ANT_SetCryptoKey_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_SetCryptoKey_RTO.restype = c_bool
    lib.ANT_SetCryptoID_RTO.argtypes = [c_void_p, POINTER(c_ubyte), c_ulong]
    lib.ANT_SetCryptoID_RTO.restype = c_bool
    lib.ANT_SetCryptoUserInfo_RTO.argtypes = [c_void_p, POINTER(c_ubyte), c_ulong]
    lib.ANT_SetCryptoUserInfo_RTO.restype = c_bool
    lib.ANT_SetCryptoRNGSeed_RTO.argtypes = [c_void_p, POINTER(c_ubyte), c_ulong]
    lib.ANT_SetCryptoRNGSeed_RTO.restype = c_bool
    lib.ANT_SetCryptoInfo_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_SetCryptoInfo_RTO.restype = c_bool
    lib.ANT_LoadCryptoKeyNVMOp_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ulong]
    lib.ANT_LoadCryptoKeyNVMOp_RTO.restype = c_bool
    lib.ANT_StoreCryptoKeyNVMOp_RTO.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_StoreCryptoKeyNVMOp_RTO.restype = c_bool
    lib.ANT_CryptoKeyNVMOp_RTO.argtypes = [c_void_p, c_ubyte, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_CryptoKeyNVMOp_RTO.restype = c_bool
    lib.ANT_WriteMessage.argtypes = [c_void_p, msg.MarshallAntMessage, c_ushort]
    lib.ANT_WriteMessage.restype = c_bool
    lib.ANT_SetCancelParameter.argtypes = [c_void_p, POINTER(c_bool)]
    lib.ANT_SetCancelParameter.restype = None
    lib.ANT_GetChannelNumber.argtypes = [c_void_p, POINTER(msg.MarshallAntMessage)]
    lib.ANT_GetChannelNumber.restype = c_ubyte
    lib.ANT_GetCapabilities.argtypes = [c_void_p, POINTER(c_ubyte), c_ubyte, c_ulong]
    lib.ANT_GetCapabilities.restype = c_bool
    lib.ANT_GetChannelID.argtypes = [c_void_p, c_ubyte, POINTER(c_ushort), POINTER(c_ubyte), POINTER(c_ubyte), c_ulong]
    lib.ANT_GetChannelID.restype = c_bool
    lib.ANT_GetChannelStatus.argtypes = [c_void_p, c_ubyte, POINTER(c_ubyte), c_ulong]
    lib.ANT_GetChannelStatus.restype = c_bool
    lib.ANT_WaitForMessage.argtypes = [c_void_p, c_ulong]
    lib.ANT_WaitForMessage.restype = c_ushort
    lib.ANT_GetMessage.argtypes = [c_void_p, POINTER(msg.MarshallAntMessage)]
    lib.ANT_GetMessage.restype = c_ushort
    lib.ANT_EnableDebugLogging.argtypes = None
    lib.ANT_EnableDebugLogging.restype = c_bool
    lib.ANT_DisableDebugLogging.argtypes = None
    lib.ANT_DisableDebugLogging.restype = None
    lib.ANT_SetDebugLogDirectory.argtypes = [c_char_p]
    lib.ANT_SetDebugLogDirectory.restype = c_bool
    lib.ANT_DebugThreadInit.argtypes = [c_char_p]
    lib.ANT_DebugThreadInit.restype = c_bool
    lib.ANT_DebugThreadWrite.argtypes = [c_char_p]
    lib.ANT_DebugThreadWrite.restype = c_bool
    lib.ANT_DebugResetTime.argtypes = None
    lib.ANT_DebugResetTime.restype = c_bool
    return lib

LIB = _load_ant_lib()

version = LIB.getUnmanagedVersion().decode('utf-8')

class ANTLibraryError(Exception):
    """A general error that indicates a problem has been encontered by ANT_LIB.

    The following message will be printed if the exception is printed:

        Error interfacing with the ANT Library!
        "error_message"
        Additional Information:
        additional_information_key1: additional_information_value1
        ...
        additional_information_keyN: additional_information_valueN
    """
    def __init__(self, error_message, **kw_args):
        """Constructs the ANTLibraryError"""
        error_message = "Error interfacing with the ANT Library!\n" + error_message
        if kw_args:
            error_message += ("\nAdditional Information:\n")
        # Set all keyword arguments as object attributes
        for attribute, value in kw_args.items():
            setattr(self, attribute, value)
            error_message += '{}: {}\n'.format(attribute, value)
        super(ANTLibraryError, self).__init__(error_message)

class ANTDeviceError(ANTLibraryError):
    """This error is designed to be returned whenever a call to AntDevice fails.

    Attributes:
        return_code         --  An optional error code provided by the call to
                                ANT_LIB. By default, this is set to None.
                                Please check the called methods for more
                                information on what the codes mean
        port                --  The port that the device was connected/
                                connecting to
        Baudrate            --  The baudrate that the device was
                                using/trying to use
        port_type           --  The type of serial part that the device was
                                using/trying to use
        serial_frame_type   --  The type of serial framer that the device
                                was using/trying to use
        return_code         --  An optional error code provided by the call
                                to ANT_LIB. By default, this is set to None.
                                Please check the called methods for more
                                information on what mthods produce codes
                                and their meanings

        The following message will be printed if the exception is printed:

        Error interfacing with ANT device!
        (operation_name) failed with return_code (only if one is provided)
        Device Details:
        Port:               (port)
        Baudrate:           (baudrate)
        Port Type :         (port_type)
        Serial Frame Type: (serial_frame_type)
    """

    def __init__(self, device, operation_name, return_code=None, **kw_args):
        """Constructs the ANTDevice error.

        Parameters:
            device              --  The device the operation failed on.
            operation_name      --  The name of the operation that failed.
            return_code         --  An optional error code provided by the call
                                    to ANT_LIB. By default, this is set to None.
                                    Please check the called methods for more
                                    information on what methods produce codes
                                    and their meanings
            kw_args             --  Additional parameters to be passed to the base
                                    exception
        """

        # Create the message to be printed to the user
        message = "Error interfacing with ANT device: {} failed".format(operation_name)
        if return_code is not None:
            message += " with return code: {}".format(return_code)
        super(ANTDeviceError, self).__init__(message, device=device, **kw_args)

class ANTDevice(object):
    #TODO: copy over docs from c-lib? or just refer to them?
    #pylint: disable=missing-docstring
    # These are things that we won't fix because we would rather match the
    # library API.
    #pylint: disable=too-many-public-methods
    #pylint: disable=too-many-arguments

    '''
    Python object for representing a single ant device. This mostly maps to the
    ANTFramer API of the C++ ant library.
    '''

    # Port types
    USB_PORT_TYPE = 0
    COM_PORT_TYPE = 1
    UART_PORT_TYPE = 2
    PORT_NAMES = collections.defaultdict(lambda: 'unknown', {
        None: 'none',
        USB_PORT_TYPE: 'usb',
        COM_PORT_TYPE: 'com',
        UART_PORT_TYPE: 'uart',
    })

    # Framer values
    FRAMER_TYPE_BASIC = 0
    FRAMER_NAMES = collections.defaultdict(lambda: 'unknown', {
        None: 'none',
        FRAMER_TYPE_BASIC: 'basic'
    })

    # init return values
    ANT_INIT_ERROR_NO_ERROR = 0
    ANT_INIT_ERROR_LIBRARY_ERROR = -1
    ANT_INIT_ERROR_INVALID_TYPE = -2
    ANT_INIT_ERROR_SERIAL_FAIL = -3

    # ANT Framer Return Codes
    ANT_FRAMER_FAIL = 0
    ANT_FRAMER_PASS = 1
    ANT_FRAMER_TIMEOUT = 2
    ANT_FRAMER_CANCELLED = 3
    ANT_FRAMER_INVALIDPARAM = 4
    DSI_FRAMER_ERROR = 0xFFFF
    DSI_FRAMER_TIMEOUT = 0xFFFE

    # Default values
    DEFAULT_RESPONSE_TIME = 0
    DEFAULT_SERIAL_LOG_NAME_PATTERN = 'Device{}.txt'

    # Array Types
    _CAPABILITIES_ARRAY = (ct.c_ubyte * msg.MESG_CAPABILITIES_SIZE)
    _USB_MAX_STRLEN = 256
    _USB_STRING = ct.c_ubyte * _USB_MAX_STRLEN

    def __init__(self, port, baudrate=57600, port_type=USB_PORT_TYPE, serial_frame_type=FRAMER_TYPE_BASIC):
        """Initializes the connection to the ANT device.

        Parameters:
            port                --  The port that the ANT device is connected to
            baudrate            --  The baudrate of the device to connect to
            port_type           --  The type of the serial port to connect to
                                    Supported port types:
                                        USB_PORT_TYPE
                                        COM_PORT_TYPE
                                        UART_PORT_TYPE
            serial_frame_type   --  The type of serial framing that should be
                                    used. Supported types:
                                        FRAMER_TYPE_BASIC

        If the call fails then an ANTDeviceError is thrown with a return code.
        Otherwise, there is no return.
        """
        # TODO: Add finalizer.
        # TODO: Add in support for autoinit once the library has support for it again.
        # TODO: Once auto-init is used we need a way to get the right device number for the logname.

        self.ant_serial_ptr = ct.c_void_p()
        self.ant_framer_ptr = ct.c_void_p()
        self.port = port
        self.baudrate = baudrate
        self.port_type = port_type
        self.serial_frame_type = serial_frame_type
        self._cancel_var = ct.pointer(ct.c_bool())

        init_response = None
        if port_type == self.UART_PORT_TYPE:
            init_response = LIB.ANT_Init_UART(self._val_to_ubyte_arr(port),
                                              baudrate,
                                              ct.byref(self.ant_serial_ptr),
                                              ct.byref(self.ant_framer_ptr),
                                              serial_frame_type)
        elif port_type == self.USB_PORT_TYPE or port_type == self.COM_PORT_TYPE:
            init_response = LIB.ANT_Init(int(port), baudrate,
                                         ct.byref(self.ant_serial_ptr),
                                         ct.byref(self.ant_framer_ptr),
                                         port_type,
                                         serial_frame_type)
        else:
            raise ANTDeviceError(self, "Initialize",
                                 ANTDevice.ANT_INIT_ERROR_INVALID_TYPE,
                                 requested_type=port_type)

        if init_response != ANTDevice.ANT_INIT_ERROR_NO_ERROR:
            # Explicitly specify requested params since they aren't set unless
            # initialization is successfull.
            raise ANTDeviceError(self, "Initialize", init_response,
                                 req_port=port,
                                 req_baud=baudrate,
                                 req_port_type=port_type,
                                 req_framer=serial_frame_type)

        # Set up the cancel var so we can cancel transfers later if needed.
        LIB.ANT_SetCancelParameter(self.ant_framer_ptr, self._cancel_var)

    def __repr__(self):
        return '<ANTDevice {}-{} ({} Baud) with {} framer>'.format(
            self.PORT_NAMES[self.port_type],
            self.port,
            self.baudrate,
            self.FRAMER_NAMES[self.serial_frame_type]
        )

    # TODO: Implement in the Unmanaged Wrapper
    @staticmethod
    def get_crc16(data, size):
        return LIB.getCRC16(data, size)

    def _check_result(self, value, operation_name):
        if value != self.ANT_FRAMER_PASS:
            raise ANTDeviceError(self, operation_name, value)

    def ant_close(self):
        if (self.ant_serial_ptr is not None and
            self.ant_framer_ptr is not None):
            LIB.ANT_Close(self.ant_serial_ptr, self.ant_framer_ptr)
        self.ant_serial_ptr.value = None
        self.ant_framer_ptr.value = None
        self.port = None
        self.baudrate = None
        self.port_type = None
        self.serial_frame_type = None

    def usb_reset(self):
        self._check_result(LIB.ANT_USBReset(self.ant_serial_ptr), 'usb_reset')

    def reset_system(self, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ResetSystem(self.ant_framer_ptr, response_time_msec),
            'reset_system')

    def set_network_key(self, netnumber, key, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(key) != msg.NETWORK_KEY_SIZE:
            raise ValueError('Network key must be 8 bytes')
        self._check_result(
            LIB.ANT_SetNetworkKey_RTO(self.ant_framer_ptr, netnumber, self._val_to_ubyte_arr(key),
                                      response_time_msec),
            'set_network_key')

    def assign_channel(self, channelnum, channeltype, netnumber, extflags=None,
                       response_time_msec=DEFAULT_RESPONSE_TIME):
        if extflags is None:
            result = LIB.ANT_AssignChannel_RTO(self.ant_framer_ptr, channelnum, channeltype,
                                               netnumber, response_time_msec)
        else:
            result = LIB.ANT_AssignChannelExt_RTO(self.ant_framer_ptr, channelnum, channeltype,
                                                  netnumber, extflags, response_time_msec)
        self._check_result(result, 'assign_channel')

    def unassign_channel(self, channelnum, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_UnAssignChannel_RTO(self.ant_framer_ptr, channelnum, response_time_msec),
            'unassign_channel')

    def set_channel_id(self, channelnum, devicenumber, devicetype, transmissiontype,
                       response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetChannelId_RTO(self.ant_framer_ptr, channelnum, devicenumber, devicetype,
                                     transmissiontype, response_time_msec),
            'set_channel_id')

    def set_channel_period(self, channelnum, period, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetChannelPeriod_RTO(self.ant_framer_ptr, channelnum, period,
                                         response_time_msec),
            'set_period')

    def set_rssi_threshold(self, channelnum, threshold, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_RSSI_SetSearchThreshold_RTO(self.ant_framer_ptr, channelnum, threshold,
                                                response_time_msec),
            'set_rssi_threshold')

    def set_low_priority_search_timeout(self, channelnum, searchtimeout,
                                        response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetLowPriorityChannelSearchTimeout_RTO(self.ant_framer_ptr, channelnum,
                                                           searchtimeout, response_time_msec),
            'set_low_priority_search_timeout')

    def set_channel_search_timeout(self, channelnum, searchtimeout,
                                   response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetChannelSearchTimeout_RTO(self.ant_framer_ptr, channelnum, searchtimeout,
                                                response_time_msec),
            'set_channel_search_timeout')

    def set_channel_freq(self, channelnum, freq, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetChannelRFFreq_RTO(self.ant_framer_ptr, channelnum, freq,
                                         response_time_msec),
            'set_channel_freq')

    def set_tx_power(self, transmitpower, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetTransmitPower_RTO(self.ant_framer_ptr, transmitpower, response_time_msec),
            'set_tx_power')

    def set_channel_tx_power(self, channelnum, transmitpower,
                             response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetChannelTxPower_RTO(self.ant_framer_ptr, channelnum, transmitpower,
                                          response_time_msec),
            'set_channel_tx_power')

    def configure_split_advanced_bursts(self, enable):
        self._check_result(
            LIB.ANT_ConfigureSplitAdvancedBursts(self.ant_framer_ptr, enable),
            'configure_split_advanced_bursts')

    def configure_advanced_burst(self, enable, maxpacketlength, requiredfields, optionalfields,
                                 stallcount=None, retrycycles=None,
                                 response_time_msec=DEFAULT_RESPONSE_TIME):
        if stallcount is None and retrycycles is None:
            result = LIB.ANT_ConfigureAdvancedBurst_RTO(self.ant_framer_ptr, enable,
                                                        maxpacketlength, requiredfields,
                                                        optionalfields, response_time_msec)
        elif stallcount is None or retrycycles is None:
            raise ValueError('Must specify both or neither of stallcount and retrycycles')
        else:
            result = LIB.ANT_ConfigureAdvancedBurst_ext_RTO(self.ant_framer_ptr, enable,
                                                            maxpacketlength, requiredfields,
                                                            optionalfields, stallcount, retrycycles,
                                                            response_time_msec)
        self._check_result(result, 'configure_advanced_burst')

    def request_message(self, channel, message_id, response_time_msec=DEFAULT_RESPONSE_TIME):
        """Requests a message from the ANT Device.

        Parameters:
            channel             --  The channel to request the message from
            message_id          --  The requested message ID
            response_time_msec  --  Timeout used to wait for the response

        If response_time_msec is non-zero this function will block for up to
        response_time_msec and return the requested message as an AntMessage.
        If the wait times out or any other error occurs an ANTDeviceError will
        be thrown. If no wait time is specified the function will return None.
        """
        response_message = msg.MarshallAntMessageItem()
        self._check_result(
            LIB.ANT_RequestMessage(self.ant_framer_ptr, channel, message_id,
                                   ct.byref(response_message), response_time_msec),
            'request_message')
        # If response_time_msec is 0 then ANT LIB only sends the request and
        # never fills in the response_message, thus there would be no point in
        # returning it
        if response_time_msec == 0:
            return None
        return response_message.tomsg()

    def open_channel(self, channelnum, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_OpenChannel_RTO(self.ant_framer_ptr, channelnum, response_time_msec),
            'open_channel')

    def close_channel(self, channelnum, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_CloseChannel_RTO(self.ant_framer_ptr, channelnum, response_time_msec),
            'close_channel')

    def send_broadcast(self, channel, data):
        if len(data) != antdefs.ANT_STANDARD_DATA_PAYLOAD_SIZE:
            raise ValueError('Broadcast data must be 8 bytes')
        self._check_result(
            LIB.ANT_SendBroadcastData(self.ant_framer_ptr, channel, self._val_to_ubyte_arr(data)),
            'send_broadcast')

    def send_ack(self, channel, data, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(data) != antdefs.ANT_STANDARD_DATA_PAYLOAD_SIZE:
            raise ValueError('Acknowledged data must be 8 bytes')
        # Library doesn't write to the cancel var at all, so clear it before starting a transfer.
        self._cancel_var[0] = False
        self._check_result(
            LIB.ANT_SendAcknowledgedData_RTO(self.ant_framer_ptr, channel,
                                             self._val_to_ubyte_arr(data), response_time_msec),
            'send_ack')

    def send_burst(self, channel, data, response_time_msec=DEFAULT_RESPONSE_TIME):
        # Library doesn't write to the cancel var at all, so clear it before starting a transfer.
        self._cancel_var[0] = False
        self._check_result(
            LIB.ANT_SendBurstTransfer_RTO(self.ant_framer_ptr, channel,
                                          self._val_to_ubyte_arr(data), len(data),
                                          response_time_msec),
            'send_burst')

    def send_adv_burst(self, channel, data, packet_size,
                       response_time_msec=DEFAULT_RESPONSE_TIME):
        # Library doesn't write to the cancel var at all, so clear it before starting a transfer.
        self._cancel_var[0] = False
        self._check_result(
            LIB.ANT_SendAdvancedBurstTransfer_RTO(self.ant_framer_ptr, channel,
                                                  self._val_to_ubyte_arr(data), len(data),
                                                  packet_size, response_time_msec),
            'send_adv_burst')

    def send_ext_broadcast(self, channel, device_number, device_type, transmit_type, data):
        if len(data) != antdefs.ANT_STANDARD_DATA_PAYLOAD_SIZE:
            raise ValueError('Broadcast data must be 8 bytes')
        self._check_result(
            LIB.ANT_SendExtBroadcastData(self.ant_framer_ptr, channel, device_number, device_type,
                                         transmit_type, self._val_to_ubyte_arr(data)),
            'send_ext_broadcast')

    def send_ext_ack(self, channel, device_number, device_type, transmit_type,
                     data, response_time_msec=DEFAULT_RESPONSE_TIME):
        # Library doesn't write to the cancel var at all, so clear it before starting a transfer.
        self._cancel_var[0] = False
        if len(data) != antdefs.ANT_STANDARD_DATA_PAYLOAD_SIZE:
            raise ValueError('Acknowledged data must be 8 bytes')
        self._check_result(
            LIB.ANT_SendExtAcknowledgedData_RTO(self.ant_framer_ptr, channel, device_number,
                                                device_type, transmit_type,
                                                self._val_to_ubyte_arr(data), response_time_msec),
            'send_ext_ack')

    def send_ext_burst(self, channel, device_number, device_type, transmit_type,
                       data, response_time_msec=DEFAULT_RESPONSE_TIME):
        # Library doesn't write to the cancel var at all, so clear it before starting a transfer.
        self._cancel_var[0] = False
        self._check_result(
            LIB.ANT_SendExtBurstTransfer_RTO(self.ant_framer_ptr, channel, device_number,
                                             device_type, transmit_type,
                                             self._val_to_ubyte_arr(data), len(data),
                                             response_time_msec),
            'send_ext_burst')

    def init_cw_test_mode(self, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_InitCWTestMode_RTO(self.ant_framer_ptr, response_time_msec),
            'init_cw_test_mode')

    def set_cw_test_mode(self, transmitpower, rfchannel, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetCWTestMode_RTO(self.ant_framer_ptr, transmitpower, rfchannel,
                                      response_time_msec),
            'set_cw_test_mode')

    def add_channel_id(self, channelnum, devicenum, devicetype, transmissiontype, listindex,
                       response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_AddChannelID_RTO(self.ant_framer_ptr, channelnum, devicenum, devicetype,
                                     transmissiontype, listindex, response_time_msec),
            'add_channel_id')

    def config_list(self, channelnum, listsize, exclude, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ConfigList_RTO(self.ant_framer_ptr, channelnum, listsize, exclude,
                                   response_time_msec),
            'config_list')

    def open_rx_scan_mode(self, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_OpenRxScanMode_RTO(self.ant_framer_ptr, response_time_msec),
            'open_rx_scan_mode')

    def enable_rx_ext_messages(self, enable, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_RxExtMesgsEnable_RTO(self.ant_framer_ptr, enable, response_time_msec),
            'enable_rx_ext_messages')

    def set_serial_num_channel_id(self, channelnum, devicetype, transmissiontype,
                                  response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetSerialNumChannelId_RTO(self.ant_framer_ptr, channelnum, devicetype,
                                              transmissiontype, response_time_msec),
            'set_serial_num_channel_id')

    def get_device_usb_pid(self):
        pid = ct.c_ushort()
        self._check_result(
            LIB.ANT_GetDeviceUSBPID(self.ant_framer_ptr, ct.byref(pid)),
            'get_device_usb_pid')
        return pid.value

    def get_device_usb_vid(self):
        vid = ct.c_ushort()
        self._check_result(
            LIB.ANT_GetDeviceUSBVID(self.ant_framer_ptr, ct.byref(vid)),
            'get_device_usb_vid')
        return vid.value

    def get_serial_string(self):
        serialstring = self._USB_STRING()
        self._check_result(
            LIB.ANT_GetDeviceSerialString(self.ant_serial_ptr,
                                          ct.cast(serialstring, ct.POINTER(ct.c_ubyte))),
            'get_serial_string')
        return str(bytearray(serialstring).split('\x00')[0])

    def get_serial_number(self):
        return LIB.ANT_GetDeviceSerialNumber(self.ant_serial_ptr)

    def get_device_serial_number(self, response_time_msec=DEFAULT_RESPONSE_TIME):
        # TODO: If a similar method is available in the library use it.
        '''
        Request the serial number of the ANT device.
        Sends a message request for the message with ID MESG_GET_SERIAL_NUM_ID (0x61)

        Parameters:
            response_time_msec - The amount of time to wait for a response in ms.

        Returns:
            If response_time_msec is 0 then None is returned. Otherwise the parsed 4-byte serial
            number will be returned. If the command timesout or an error response is received then
            an ANTDeviceError will be thrown.
        '''
        response = self.request_message(0, msg.MESG_GET_SERIAL_NUM_ID, response_time_msec)
        if response is None:
            return None
        return (response.data[0] |
                (response.data[1] << 8) |
                (response.data[2] << 16) |
                (response.data[3] << 24))

    def get_version(self, version_id=0, response_time_msec=DEFAULT_RESPONSE_TIME):
        """Retrieves the version number for a specific index.

        Raises an ANTDeviceError if the operation fails
        """
        try:
            response = self.request_message(version_id, msg.MESG_VERSION_ID,
                                            response_time_msec)
        except ANTDeviceError as error:
            raise ANTDeviceError(self, "get_version", root_cause=error)
        if response_time_msec == 0:
            return None
        # convert to string, making sure we stop at the first null.
        version = str(
            bytearray(response.data).split(b'\x00')[0].decode('utf-8'))
        return version

    @staticmethod
    def get_num_devices():
        return LIB.ANT_GetNumDevices()

    def crystal_enable(self, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_CrystalEnable(self.ant_framer_ptr, response_time_msec),
            'crystal_enable')

    def set_lib_config(self, libconfigflags, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetLibConfig(self.ant_framer_ptr, libconfigflags, response_time_msec),
            'set_lib_config')

    def set_proximity_threshold(self, channelnum, searchthreshold,
                                response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetProximitySearch(self.ant_framer_ptr, channelnum, searchthreshold,
                                       response_time_msec),
            'set_proximity_threshold')

    def config_frequency_agility(self, channelnum, freq1, freq2, freq3,
                                 response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ConfigFrequencyAgility(self.ant_framer_ptr, channelnum, freq1, freq2, freq3,
                                           response_time_msec),
            'config_frequency_agility')

    def config_event_buffer(self, config, size, time, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ConfigEventBuffer(self.ant_framer_ptr, config, size, time, response_time_msec),
            'config_event_buffer')

    def config_event_filter(self, eventfilter, response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ConfigEventFilter(self.ant_framer_ptr, eventfilter, response_time_msec),
            'config_event_filter')

    def config_high_duty_search(self, enable, suppressioncycles,
                                response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ConfigHighDutySearch(self.ant_framer_ptr, enable, suppressioncycles,
                                         response_time_msec),
            'config_high_duty_search')

    def config_selective_data_update(self, channelnum, sduconfig,
                                     response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ConfigSelectiveDataUpdate(self.ant_framer_ptr, channelnum, sduconfig,
                                              response_time_msec),
            'config_selective_data_update')

    def set_selective_data_update_mask(self, masknumber, sdumask,
                                       response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetSelectiveDataUpdateMask(self.ant_framer_ptr, masknumber,
                                               self._val_to_ubyte_arr(sdumask), response_time_msec),
            'set_selective_data_update_mask')

    def set_channel_search_priority(self, channelnum, prioritylevel,
                                    response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_SetChannelSearchPriority(self.ant_framer_ptr, channelnum, prioritylevel,
                                             response_time_msec),
            'set_channel_search_priority')

    def encrypted_channel_enable(self, channelnum, mode, volatilekeyindex, decimationrate,
                                 response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_EncryptedChannelEnable_RTO(self.ant_framer_ptr, channelnum, mode,
                                               volatilekeyindex, decimationrate,
                                               response_time_msec),
            'encrypted_channel_enable')

    def add_crypto_id(self, channelnum, data, listindex, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(data) != msg.CRYPTO_ID_SIZE:
            raise ValueError('Crypto IDs must be 4 bytes.')
        self._check_result(
            LIB.ANT_AddCryptoID_RTO(self.ant_framer_ptr, channelnum,
                                    ct.byref(self._val_to_ubyte_arr(data)), listindex,
                                    response_time_msec),
            'add_crypto_id')

    def config_crypto_list(self, channelnum, listsize, blacklist,
                           response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_ConfigCryptoList_RTO(self.ant_framer_ptr, channelnum, listsize, blacklist,
                                         response_time_msec),
            'config_crypto_list')

    def set_crypto_key(self, volatilekeyindex, key, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(key) != msg.CRYPTO_KEY_SIZE:
            raise ValueError('Crypto keys must be 16 bytes.')
        self._check_result(
            LIB.ANT_SetCryptoKey_RTO(self.ant_framer_ptr, volatilekeyindex,
                                     self._val_to_ubyte_arr(key), response_time_msec),
            'set_crypt_key')

    def set_crypto_id(self, data, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(data) != msg.CRYPTO_ID_SIZE:
            raise ValueError('Crypto IDs must be 4 bytes.')
        self._check_result(
            LIB.ANT_SetCryptoID_RTO(self.ant_framer_ptr,
                                    self._val_to_ubyte_arr(data), response_time_msec),
            'set_crypto_id')

    def set_crypto_user_info(self, data, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(data) != msg.CRYPTO_USER_DATA_SIZE:
            raise ValueError('User Data must be 19 bytes.')
        self._check_result(
            LIB.ANT_SetCryptoUserInfo_RTO(self.ant_framer_ptr, self._val_to_ubyte_arr(data),
                                          response_time_msec),
            'set_crypto_user_info')

    def set_crypto_rng_seed(self, data, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(data) != msg.CRYPTO_KEY_SIZE:
            raise ValueError('RNG seed must be 16 bytes.')
        self._check_result(
            LIB.ANT_SetCryptoRNGSeed_RTO(self.ant_framer_ptr, self._val_to_ubyte_arr(data),
                                         response_time_msec),
            'set_crypto_rng_seed')

    # no generic set info because we can't check length that way. Add new specific functions for
    # for any new things that can be set through set_info.

    def load_crypto_key_nvm(self, nvmkeyindex, volatilekeyindex,
                            response_time_msec=DEFAULT_RESPONSE_TIME):
        self._check_result(
            LIB.ANT_LoadCryptoKeyNVMOp_RTO(self.ant_framer_ptr, nvmkeyindex, volatilekeyindex,
                                           response_time_msec),
            'load_crypto_key_nvm')

    def store_crypto_key_nvm(self, nvmkeyindex, key, response_time_msec=DEFAULT_RESPONSE_TIME):
        if len(key) != msg.CRYPTO_KEY_SIZE:
            raise ValueError('Crypto keys must be 16 bytes.')
        self._check_result(
            LIB.ANT_StoreCryptoKeyNVMOp_RTO(self.ant_framer_ptr, nvmkeyindex, ct.byref(key),
                                            response_time_msec),
            'store_crypto_key_nvm')

    def write_message(self, antmessage):
        marshall = msg.MarshallAntMessageItem(antmessage)
        self._check_result(
            LIB.ANT_WriteMessage(self.ant_framer_ptr, marshall.message, marshall.size),
            'write_message')

    def cancel_transfer(self):
        self._cancel_var[0] = True

    def get_channel_number(self, antmessage):
        marshall = msg.MarshallAntMessageItem(antmessage)
        return LIB.ANT_GetChannelNumber(self.ant_framer_ptr, ct.byref(marshall.message))

    def get_capabilities(self, response_time_msec=DEFAULT_RESPONSE_TIME):
        """"Retrieves the device capabilities as a list.

        If the operation fails, then a ANTDeviceError is raised.
        """

        capabilities = ANTDevice._CAPABILITIES_ARRAY()
        self._check_result(
            LIB.ANT_GetCapabilities(self.ant_framer_ptr, capabilities,
                                    len(capabilities),
                                    response_time_msec),
            'get_capabilities')
        if response_time_msec == 0:
            return None
        return capabilities[:]

    def get_channel_id(self, channelnum, response_time_msec=DEFAULT_RESPONSE_TIME):
        devicenumber = ct.c_ushort()
        devicetype = ct.c_ubyte()
        transmittype = ct.c_ubyte()
        self._check_result(
            LIB.ANT_GetChannelID(self.ant_framer_ptr, channelnum, ct.byref(devicenumber),
                                 ct.byref(devicetype), ct.byref(transmittype), response_time_msec),
            'get_channel_id')
        if response_time_msec == 0:
            return None
        return (devicenumber.value, devicetype.value, transmittype.value)

    def get_channel_status(self, channel, response_time_msec=DEFAULT_RESPONSE_TIME):
        """Queries the ant device for the status of the specified channel.

        Parameters:
            channel         --  The channel number to query
            response_time   --  The time to wait until a response arrives
                                By default the value is 0 which signify a 0
                                sec timeout. This means that the call is non
                                blocking and that the status is not returned

        Returns the status as an integer. Otherwise if there is an issue or the
        the timeout expires a ANTDeviceError is thrown.
        """
        channel_status = ct.c_ubyte()
        self._check_result(
            LIB.ANT_GetChannelStatus(self.ant_framer_ptr, channel, ct.byref(channel_status),
                                     response_time_msec),
            'get_channel_status')
        if response_time_msec == 0:
            return None
        return channel_status.value

    def wait_for_message(self, response_time_msec=DEFAULT_RESPONSE_TIME):
        """Waits for an ANT message for a certain time.

        Parameters:
            response_time_msec  --  The time to wait for a message in
                                    milliseconds

        Return:
            A boolean indicating whether there is a message in the rx queue or
            not.

        This function blocks until there is a message in the rx queue or it
        times out waiting.
        """
        message_size = LIB.ANT_WaitForMessage(self.ant_framer_ptr,
                                              response_time_msec)

        if message_size == self.DSI_FRAMER_TIMEOUT:
            return False
        if message_size == self.DSI_FRAMER_ERROR:
            raise ANTDeviceError(self, 'wait_for_message')
        return True

    def get_message(self):
        """Returns the first message in the framer's received buffer.

        If there is an available message in the rx queue it will be returned as
        an instance of AntMessage. Otherwise None will be returned.
        """
        received_message = msg.MarshallAntMessageItem()
        # Retrieve the ant message and check for errors
        message_size = LIB.ANT_GetMessage(self.ant_framer_ptr, ct.byref(received_message.message))
        if message_size == self.DSI_FRAMER_TIMEOUT:
            return None
        if message_size == self.DSI_FRAMER_ERROR:
            raise ANTDeviceError(self, 'get_message')

        # If no errors are detected then fill in the size parameter and return
        # the message
        received_message.size = message_size
        return received_message.tomsg()

    ############################################################################
    # Logging Methods
    ############################################################################

    def get_serial_log_name(self):
        """Retrieves the name of the serial log files for this device.

        Note, there is no guarantee that the serial log file exists.
        """
        return ANTDevice.DEFAULT_SERIAL_LOG_NAME_PATTERN.format(
            self.port)

    @staticmethod
    def enable_debug_logging():
        """Enable ANT_LIB to start logging Thread and Serial events.

        By default, the log directory is the current working directory of the
        process.

        Raises ANTLibraryError if logging can't be enabled.
        """
        if not LIB.ANT_EnableDebugLogging():
            raise ANTLibraryError('Error Enabling Debug Logging')

    @staticmethod
    def disable_debug_logging():
        """Disable all serial and thread logging by ANT_LIB."""
        LIB.ANT_DisableDebugLogging()

    @staticmethod
    def set_debug_log_directory(directory):
        """Sets ANT_LIB's logging directory for both the serial and thread
        logging.

        Parameters:
            directory   --  The new directory to log to

        Note: If the directory does not end with a directory separator e.g.
        directory = "test/dir" then the logs will be created inside the
        test directory and their names will be prefixed with dir.
        (test/dirDevice1.txt)

        Raises a ANTLibraryError if the logging directory can't be changed. The
        exception has the field directory.
        """
        if not LIB.ANT_SetDebugLogDirectory(directory):
            raise ANTLibraryError('Error Changing Debug Logging Directory',
                                  directory=directory)

    @staticmethod
    def debug_thread_init(file_name):
        """Initializes an ANT_LIB logger that is associated with the current
        thread.

        Parameters:
            file_name   --  The file name does not need to include the extension
                            .txt is automatically appended to it

        Raises ANTLibraryError if the thread logs can't be initialized. The
        error will have the file_name attribute set on it.
        """
        if not LIB.ANT_DebugThreadInit(file_name):
            raise ANTLibraryError('Error Initializing Thread Debug Logging',
                                  file_name=file_name)

    @staticmethod
    def debug_thread_write(message):
        """Writes a message to the thread specific ANT_LIB logger.

        Parameters:
            message --  The string message to log

        Raises ANTLibraryError if the log operation failed. The error has the
        message attribute set on it.
        """
        if not LIB.ANT_DebugThreadWrite(message):
            raise ANTLibraryError('Error Writing To Thread Debug Logs',
                                  message=message)

    @staticmethod
    def debug_reset_time():
        """Reset the time used to stamp each message logged through ANT_LIB.

        Appends "New Session." to all log files.

        Raises ANTLibraryError if the operation failed.
        """
        if not LIB.ANT_DebugResetTime():
            raise ANTLibraryError('Error Resetting Debug Time')

    ############################################################################
    # Utility Methods
    ############################################################################
    @staticmethod
    def _val_to_ubyte_arr(value):
        """This method convers a String or List into a byte array which is used
        by ANTLIB

        Parameters:
            value -- A List or String to convert to a byte array
        """
        return_buffer = (ct.c_ubyte * len(value))

        #Special case for strings.
        if isinstance(value, str):
            return return_buffer.from_buffer_copy(value)

        return return_buffer(*value)

    def __enter__(self):
        return self

    def __del__(self):
        self.ant_close()

    def __exit__(self, exception_type, exception_value, traceback):
        self.ant_close()
