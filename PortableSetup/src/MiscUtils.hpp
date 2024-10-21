#pragma once

#include <string>
#include <vector>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_PRIO_VALUE(class, data) (((class) << IOPRIO_CLASS_SHIFT) | data)

#define millis() (duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count())
#define micros() (duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count())

#define DIFF_TIMESPEC_NS(START, END) ((END.tv_sec - START.tv_sec) * (long)1e9 + (END.tv_nsec - START.tv_nsec))
#define DIFF_TIMESPEC_US(START, END) (DIFF_TIMESPEC_NS(START, END) / 1000)

#define COLOR_RESET "\033[00m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED "\033[31m"
#define COLOR_CYAN "\033[36m"
#define COLOR_MAGENTA "\033[35m"

#define GL1(...) fmt::print("{}\n", fmt::format(__VA_ARGS__))
#define GL1G(...) fmt::print(COLOR_GREEN "{}" COLOR_RESET "\n", fmt::format(__VA_ARGS__))
#define GL1Y(...) fmt::print(COLOR_YELLOW "{}" COLOR_RESET "\n", fmt::format(__VA_ARGS__))
#define GL1R(...) fmt::print(COLOR_RED "{}" COLOR_RESET "\n", fmt::format(__VA_ARGS__))
#define GL1C(...) fmt::print(COLOR_CYAN "{}" COLOR_RESET "\n", fmt::format(__VA_ARGS__))
#define GL1M(...) fmt::print(COLOR_MAGENTA "{}" COLOR_RESET "\n", fmt::format(__VA_ARGS__))

#define CLASS_NAME(x) boost::typeindex::type_id_with_cvr<x>().pretty_name()
#define CLASS_NAME_INST(x) boost::typeindex::type_id_with_cvr<decltype(x)>().pretty_name()

extern "C" const char *__progname;

enum {
    IOPRIO_CLASS_NONE,
    IOPRIO_CLASS_RT,
    IOPRIO_CLASS_BE,
    IOPRIO_CLASS_IDLE,
};

enum {
    IOPRIO_WHO_PROCESS = 1,
    IOPRIO_WHO_PGRP,
    IOPRIO_WHO_USER,
};

std::string ProcessName()
{
    std::string sp;
    std::ifstream("/proc/self/comm") >> sp;
    return sp;
}

int ProcessExec(std::string cmd, bool verbose = false, double timeout_seconds = 5.0)
{
    std::array<char, 1024> buffer;
    if (verbose)
        GL1("{}", cmd);

    cmd = fmt::format("timeout --preserve-status -k {} -s QUIT {} {}", timeout_seconds + 2.0, timeout_seconds, cmd);
    FILE *proc = popen(cmd.c_str(), "r");
    int ret = pclose(proc);
    if (verbose && ret)
        GL1("Error: Command \"{}\" failed: {}", cmd, strerror(errno));
    return ret;
}

inline std::vector<std::string> string_split(std::string &str, const std::string &delim)
{
    std::vector<std::string> str_list;
    strtk::parse(str, delim, str_list);
    return str_list;
}

inline std::vector<std::string> string_split(const char *str, const std::string &delim)
{
    std::vector<std::string> str_list;
    strtk::parse(str, delim, str_list);
    return str_list;
}

inline bool string_contains(const std::string &str, const std::string &substr)
{
    return (str.find(substr) != std::string::npos);
}

inline bool string_begins(const std::string &str, const std::string &substr)
{
    return (str.rfind(substr, 0) == 0);
}

inline std::string string_file_extension(std::string &str)
{
    std::string file_name = string_split(str, "/").back();
    auto str_ext = string_split(file_name, ".");

    if (str_ext.size() > 1)
        return str_ext.back();
    else
        return "";
}

// Check if a given folder exists and create one if not
void EnsureFolder(std::string folder_path, int user = 1000, int group = 1000, std::string perm_str = "0755")
{
    std::ifstream f(folder_path);

    if (f.good())
        return;

    ProcessExec(fmt::format("mkdir -p {}", folder_path));
    ProcessExec(fmt::format("chown {}:{} {}", user, group, folder_path));
    ProcessExec(fmt::format("chmod {} {}", perm_str, folder_path));
}

static inline int ioprio_set(int which, int who, int ioprio)
{
    return syscall(SYS_ioprio_set, which, who, ioprio);
}



static bool enable_rt_scheduler(uint8_t use_full_time = 0)
{
    // Configure hard limits
    system(("prlimit --rtprio=unlimited:unlimited --pid " + std::to_string(getpid())).c_str());
    system(("prlimit --nice=unlimited:unlimited --pid " + std::to_string(getpid())).c_str());

    // Set schedule priority
    struct sched_param sp;
    int policy = 0;

    sp.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_t this_thread = pthread_self();

    int ret = sched_setscheduler(0, SCHED_FIFO, &sp);
    if (ret) {
        GL1R("Error: sched_setscheduler: Failed to change scheduler to RR");
        return false;
    }

    ret = pthread_getschedparam(this_thread, &policy, &sp);
    if (ret) {
        GL1R("Error: Couldn't retrieve real-time scheduling parameters");
        return false;
    }

    // LOG2G("Thread priority is ", sp.sched_priority);

    // Allow thread to be cancelable
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    // Set IO prioriy
    ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 0));

    if (use_full_time) {
        int fd = ::open("/proc/sys/kernel/sched_rt_runtime_us", O_RDWR);
        if (fd) {
            if (::write(fd, "-1", 2) > 0)
                GL1R("/proc/sys/kernel/sched_rt_runtime_us = -1");
        }
    }

    return true;
}

static void enable_idle_scheduler()
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGABRT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    // Set schedule priority to IDLE (lowest)
    struct sched_param sp;
    sp.sched_priority = sched_get_priority_min(SCHED_IDLE);
    pthread_setschedparam(pthread_self(), SCHED_IDLE, &sp);
    // Allow thread to be cancelable
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
}

static std::string bytes_to_hex(uint8_t *buf, uint16_t size)
{
    std::stringstream ss;
    for (int i = 0; i < size; ++i) {
        ss << fmt::format("{:02X}", buf[i]);
    }
    return ss.str();
}

template <typename T>
class list_data : public lni::fast_vector<T> {
    lni::fast_vector<int> slices;

    list_data() = default;

    list_data(lni::fast_vector<T> &new_data)
        : lni::fast_vector<T>(new_data)
    {
    }

    list_data(uint8_t *buf, size_t buf_size)
        : lni::fast_vector<T>(buf, buf + buf_size)
    {
    }

    int slice_last_offset() const
    {
        if (slices.size())
            return slices.back();
        else
            return 0;
    }

    int slice_last_size() const
    {
        if (slices.size())
            return this->size() - slices.back();
        else
            return 0;
    }

    int slice_offset(int pos) const
    {
        if (slices.size())
            return slices[pos];
        else
            return 0;
    }

    int slice_size(int pos) const
    {
        if (slices.size() > pos + 1)
            return slices[pos + 1] - slices[pos];
        else if (slices.size() == pos + 1)
            return this->size() - slices.back();
        else
            return 0;
    }

    T index(int pos) const
    {
        return this->at(pos);
    }

    const char *c_str() const
    {
        return (const char *)&this->at(0);
    }

    std::string str() const
    {
        return string((const char *)&this->at(0), this->size());
    }

    std::string hex()
    {
        return strtk::convert_bin_to_hex(string((char *)&this->at(0), this->size()));
    }

    const char *slice_c_str(int slice_pos)
    {
        return &this->at(slices[slice_pos]);
    }

    inline void slice()
    {
        slices.push_back(this->size());
    }

    inline std::string get_slice(int idx)
    {
        int offset = slice_offset(idx);
        return string((char *)&this->at(offset), slice_size(idx));
    }

    inline lni::fast_vector<uint8_t> get_slice_buf(int idx)
    {
        int offset = slice_offset(idx);
        return lni::fast_vector<uint8_t>((uint8_t *)&this->at(offset), (uint8_t *)&this->at(offset) + slice_size(idx));
    }

    void append(lni::fast_vector<T> &src_buf)
    {
        this->insert(this->end(), src_buf.begin(), src_buf.end());
    }

    void append_slice(lni::fast_vector<T> &src_buf)
    {
        slice();
        this->insert(this->end(), src_buf.begin(), src_buf.end());
    }

    void append(T val)
    {
        this->push_back(val);
    }

    void append_slice(T val)
    {
        slice();
        this->push_back(val);
    }

    void append(uint8_t *buf, size_t buf_size)
    {
        this->insert(this->end(), buf, buf + buf_size);
    }

    void append_slice(uint8_t *buf, size_t buf_size)
    {
        slice();
        this->insert(this->end(), buf, buf + buf_size);
    }

    list_data<T> &operator+(T val)
    {
        this->push_back(val);
        return *this;
    }

    list_data<T> &operator+(lni::fast_vector<T> &src_buf)
    {
        this->insert(this->end(), src_buf.begin(), src_buf.end());
        return *this;
    }

    void pop()
    {
        this->pop_back();
    }
};

// Received when BLE_ADV_CONNECT_REQ PDU is receiveed via serial
typedef struct __attribute__((packed)) _connection_t {
    uint32_t access_address;
    uint32_t crc_init : 24;
    uint8_t window_size;
    uint16_t window_offset;
    uint16_t interval;
    uint16_t latency;
    uint16_t timeout; // Supervision Timeout not taken into account
    uint8_t channel_map[5];
    uint8_t hop_increment : 5;
    uint8_t sca : 3; // SCA - Sleep clock accuracy not taken into account
} connection_t;

class priority_mutex {
    std::condition_variable cv_;
    std::mutex gate_;
    bool locked_;
    std::thread::id pr_tid_; // priority thread
public:
    priority_mutex() : locked_(false) {}
    ~priority_mutex() { assert(!locked_); }
    priority_mutex(priority_mutex &) = delete;
    priority_mutex operator=(priority_mutex &) = delete;

    void lock(bool privileged = false)
    {
        const std::thread::id tid = std::this_thread::get_id();
        std::unique_lock<decltype(gate_)> lk(gate_);

        if (privileged)
            pr_tid_ = tid;
        cv_.wait(lk, [&] {
            return !locked_ && (pr_tid_ == std::thread::id() || pr_tid_ == tid);
        });
        locked_ = true;
    }

    void unlock()
    {
        std::lock_guard<decltype(gate_)> lk(gate_);
        if (pr_tid_ == std::this_thread::get_id())
            pr_tid_ = std::thread::id();
        locked_ = false;
        cv_.notify_all();
    }
};
