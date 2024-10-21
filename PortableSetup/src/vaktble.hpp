#pragma once

// C includes
#include <fcntl.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifdef __cplusplus
// C++ includes
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// Libraries includes
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <argparse/argparse.hpp>
#include <boost/type_index.hpp>
#include <fmt/color.h>
#include <fmt/core.h>
#include <libs/folly/folly/concurrency/UnboundedQueue.h>
#include <libs/strtk.hpp>
#include <libs/termcolor.hpp>
#include <react-cpp/reactcpp.h>
#include <serial/serial.h>
#include <wdissector.h>

// Project includes
using namespace std;
#include "MiscUtils.hpp" // Shall be always first

#include "Framework.hpp"
#include "PacketLogger.hpp"
#include "nRF52840.hpp"

#endif