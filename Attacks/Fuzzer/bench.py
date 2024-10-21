from binascii import hexlify
from threading import Thread, Lock
import time
import csv
import datetime

from socketIO_client import SocketIO, LoggingNamespace
import pygmo as pg
import numpy as np
import matplotlib.pyplot as plt
from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput
from pycallgraph import Config
from pycallgraph import GlobbingFilter

config = Config()
config.trace_filter = GlobbingFilter(exclude=[
    'pycallgraph.*',
    'socketIO_client.*',
    'numpy.*',
    'cookielib.*',
    'socket.*',
    'threading.*',
    'httplib.*',
    'mimetools.*',
    'rfc822.*',
    'encodings.*',
    'atexit.*',
    'codecs.*',
    'contextlib.*',
    'abc.*',
    'collections.*',
    '_abcoll.*',
    'posixpath.*',
    'json.*',
    'copy.*',
    'netrc.*',
    'Queue.*',
    'urllib.*',
    'UserDict.*',
    '__new__',
    'urlparse.*',
    'logging.*',
    'genericpath.*',
    'shlex.*',
    'shlex.*',
    '_weakrefset.*',
])

graphviz = GraphvizOutput(output_file='filter_none.png')


class InterfaceThread(Thread):
    iteration_lock = Lock()
    FuzzerParams = []
    iteration = 0

    transitions = 0
    issue_count = 0
    issue_total_count = 0
    issue_period = 0
    iteration_time = 0

    socket = None
    tracing = None

    FitnessGraph = {
        'X': [],
        'Y': [],
        'Y1': [],
        'ISSUES': [],
        'TIME': []
    }

    def init(self):
        self.iteration_lock.acquire()
        self.socket = SocketIO('localhost', 3000, LoggingNamespace)
        self.socket.emit('GetFuzzerConfig', self.getInitConfig)
        self.socket.wait_for_callbacks()

    def run(self):
        self.socket.on('Iteration', self.iteration_callback)
        self.socket.wait()

    def iteration_callback(self, data):
        self.iteration = data['Iteration']

        self.transitions = data['Transitions']
        self.issue_count = data['IssueCount']
        self.issue_period = data['IssuePeriod']
        self.iteration_time = data['IterTime']

        self.issue_total_count = data['IssueTotalCount']
        try:
            self.iteration_lock.release()
        except:
            # print('Lock already released')
            pass

    def getInitConfig(self, data):
        global FuzzerParams
        self.FuzzerParams = data

    def SetConfig(self, data):
        self.socket.emit('SetFuzzerConfig', list(data))
        pass


class WiFiCostFunction:
    counter = 0
    interface = []  # type: list(InterfaceThread)

    def __init__(self, dim, interface):
        self.dim = dim
        self.interface.append(interface)

    def fitness(self, x):
        # Send new fuzzing data
        x_int = [int(value) for value in x]
        print('Input (' + str(len(x)) + '): ' + str(x_int))
        self.interface[0].SetConfig(x_int)
        self.interface[0].iteration_lock.acquire()

        # Choose one of the following cost functions

        # wifi_fitness = - self.interface[0].transitions
        # wifi_fitness = self.interface[0].issue_period
        wifi_fitness = self.interface[0].iteration_time
        # wifi_fitness = - self.interface[0].issue_count
        # After one iteration, retrieves values
        self.counter += 1

        ret = [wifi_fitness]

        interface_handler.FitnessGraph['Y'].append(self.interface[0].issue_count)
        interface_handler.FitnessGraph['X'].append(int(self.counter))
        interface_handler.FitnessGraph['Y1'].append(ret[0])
        interface_handler.FitnessGraph['ISSUES'].append(self.interface[0].issue_total_count)
        interface_handler.FitnessGraph['TIME'].append(str(datetime.datetime.now()))

        print('Iteration: ' + str(self.interface[0].iteration) + ' Fitness: ' + str(ret))
        return ret

    def get_bounds(self):
        return [0] * self.dim, [100] * self.dim


x = PyCallGraph(output=graphviz, config=config)
x.start()

interface_handler = InterfaceThread()
interface_handler.daemon = True
interface_handler.init()
interface_handler.start()

prob = pg.problem(WiFiCostFunction(len(interface_handler.FuzzerParams), interface_handler))
# algo = pg.algorithm(pg.sga(gen=1000))
algo = pg.algorithm(pg.pso(gen=398))  # 1000 Iteration (5 per generation - 200)
algo.set_verbosity(1)
print('Initializing population...')
pop = pg.population(prob, 5)

for (idx, val) in enumerate(pop.get_x()):
    # Set all population to reference vector
    pop.set_x(idx, interface_handler.FuzzerParams)
print('Population filled with reference values')
print(interface_handler.FuzzerParams)
print(pop)

pop = algo.evolve(pop)

x.stop()
x.done()

uda = algo.extract(pg.pso)
log = uda.get_log()

with open('logs/graph.csv', 'w') as csvfile:
    columns = ['X', 'Y', 'Y1', 'ISSUES', 'TIME']
    writer = csv.DictWriter(csvfile, fieldnames=columns)
    writer.writeheader()
    for (idx, x) in enumerate(interface_handler.FitnessGraph['X']):
        writer.writerow({
            'X': x,
            'Y': interface_handler.FitnessGraph['Y'][idx],
            'Y1': interface_handler.FitnessGraph['Y1'][idx],
            'ISSUES': interface_handler.FitnessGraph['ISSUES'][idx],
            'TIME': interface_handler.FitnessGraph['TIME'][idx]
        })

print(log)
print(pop.champion_f)
f = open('logs/log.txt', 'w')
f.write('LOG\n')
f.write(str(uda.get_log()) + '\n\n\n')
f.write('BEST FITNESS\n')
f.write(str(pop.champion_f) + '\n\n\n')
f.write('POPULATION\n')
f.write(str(pop.get_x()) + '\n\n\n')
f.write('FITNESS PER INDIVIDUAL\n')
f.write(str(pop.get_f()) + '\n\n\n')
f.close()

s = [entry[0] for entry in log], [entry[2] for entry in log]
print('log entries')
print(s)
plt.plot([entry[0] for entry in log], [entry[2] for entry in log], 'k--')
plt.show()
