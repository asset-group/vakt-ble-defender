# Common imports
import threading
import json
import logging
import os
from time import sleep, time
# Flask imports
from flask import Flask, request
from flask_socketio import SocketIO
from colorama import Fore, Back

model = None
clientConected = 0
app = Flask(__name__)
socket = SocketIO(app, async_mode='threading', logger=False, engineio_logger=False, cors_allowed_origins='*')
boot_time = None


def flaskServer():
    socket.run(app, host='0.0.0.0', port=3000)


def start_webserver(model_instance):
    global model, clientConected, app, boot_time
    model = model_instance
    app.debug = False
    app.logger.disabled = True
    log = logging.getLogger('werkzeug')
    log.disabled = True
    flask = threading.Thread(target=flaskServer)
    flask.daemon = True
    boot_time = time()
    flask.start()
    print(Fore.YELLOW + 'SocketIO Webserver started')


def send_graph():
    global clientConected
    if clientConected:
        g = model.get_graph()
        g.graph_attr.update(size="15.0,8.0")
        socket.emit('GraphUpdate', {'graph': g.to_string(), 'stateName': model.state})


@app.route('/')
def index():
    return 'hello'


@socket.on('connect')
def connect():
    global clientConected
    clientConected += 1
    print('Web server connection')
    if model is None:
        return
    send_graph()


@socket.on('disconnect')
def disconnect():
    global clientConected
    clientConected -= 1
    print('disconnect ')


@socket.on('ResetMachineState')
def ResetMachineState():
    if model is None:
        return
    try:
        model.machine.reset_machine()
    except:
        return 'ERROR'
    return 'OK'


@socket.on('SignalCrash')
def SignalCrash():
    if model is None:
        return
    model.monitor_crash_detected()


def send_vulnerability(code, message, error=False):
    if clientConected:
        socket.emit('Vulnerability', {'code': code, 'message': message, 'error': error})


def send_fitness(issue_count, issue_period, iteration_transitions, iteration_time, iteration_number, issue_total):
    if clientConected:
        socket.emit('Iteration', {'IssueCount': issue_count, 'IssuePeriod': issue_period,
                                  'Transitions': iteration_transitions, 'IterTime': iteration_time,
                                  'Iteration': iteration_number, 'IssueTotalCount': issue_total})


@socket.on('GraphDot')
def graphString():
    if model is None:
        return
    g = model.get_graph()
    g.graph_attr.update(size="15.0,8.0")
    return g.to_string()


@socket.on('GetFuzzerConfig')
def GetFuzzerConfig():
    global states_fuzzer_config
    config = []

    for state in states_fuzzer_config:
        state_config = states_fuzzer_config[state]
        for attribute_name in state_config.field_names:
            val = getattr(state_config, attribute_name)
            val_type = type(val)
            if val_type is int:
                config.append(val)
            elif val_type is list:
                if len(val) > 0 and type(val[0]) is int:
                    config += val

    return config


@socket.on('Reset')
def Reset():
    request.environ.get('werkzeug.server.shutdown')()
    os.kill(os.getpid(), 2)


@socket.on('GetBootTime')
def GetFuzzerConfig():
    if model is None:
        return
    return boot_time


@socket.on('GetFitness')
def GetFitness():
    if model is None:
        return
    IssuePeriod = fitness.IssuePeriod
    if IssuePeriod == float("inf"):
        IssuePeriod = 0
    IterationTime = fitness.IterationTime
    if IterationTime == float("inf"):
        IterationTime = 0

    obj = {'IssueCount': fitness.IssueCounter,
           'IssuePeriod': IssuePeriod,
           'Transitions': fitness.TransitionLastCount,
           'IterTime': IterationTime,
           'Iteration': model.iterations,
           'IssueTotalCount': fitness.IssuesTotalCounter}
    return json.dumps(obj) + '\n'


@socket.on('GetModelConfig')
def GetModelConfig():
    if model is None:
        try:
            f = file(model.config_file, 'r')
            return f.read()
        except:
            return '{}'
    return model.get_config()


@socket.on('SetModelConfig')
def SetModelConfig(data):
    global model
    f = file(model.config_file, 'w')
    f.write(json.dumps(data, indent=4))
    f.close()
    request.environ.get('werkzeug.server.shutdown')()
    os.kill(os.getpid(), 2)


@socket.on('SetFuzzerConfig')
def SetFuzzerConfig(config):
    global states_fuzzer_config
    print(Back.WHITE + Fore.BLACK + 'Fuzzing input set to: ' + str(config))
    idx = 0
    for state in states_fuzzer_config:
        state_config = states_fuzzer_config[state]
        for attribute_name in state_config.field_names:
            val = getattr(state_config, attribute_name)
            val_type = type(val)
            if val_type is int:
                setattr(state_config, attribute_name, config[idx])
                idx += 1
            elif val_type is list:
                val_len = len(val)
                if val_len > 0 and type(val[0]) is int:
                    setattr(state_config, attribute_name, config[idx:idx + val_len])
                    idx += val_len


def SetFuzzerConfig(fuzz_cfg):
    global states_fuzzer_config
    states_fuzzer_config = fuzz_cfg
