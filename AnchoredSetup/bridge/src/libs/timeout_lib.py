from threading import Timer

global_timers = {}


def disable_timeout(timer_name):
    global global_timers
    if timer_name in global_timers:
        timer = global_timers[timer_name]
        if timer:
            timer.cancel()
            timer.cancel()
            global_timers[timer_name] = None


def start_timeout(timer_name, seconds, callback):
    global global_timers
    disable_timeout(timer_name)

    timer = Timer(seconds, callback)
    global_timers[timer_name] = timer
    timer.daemon = True
    timer.setName(timer_name)
    timer.start()


def update_timeout(timer_name):
    global global_timers
    if timer_name in global_timers:
        timer = global_timers[timer_name]

        if timer:
            timer.cancel()
            start_timeout(timer_name, timer.interval, timer.function)
