from threading import Timer, Thread
import inspect
import sys
from transitions.extensions import HierarchicalGraphMachine
from transitions.extensions.states import add_state_features, Tags, _LOGGER
from transitions.core import State, listify
from transitions.extensions.diagrams import TransitionGraphSupport
from transitions.extensions.nesting import NestedTransition
from webserver import start_webserver, send_graph, send_vulnerability
from scapy.utils import wrpcap
from scapy.packet import Packet
from colorama import Fore
import fitness


class StdOutHook:
    def write(self, data):
        sys.__stdout__.write(data + Fore.RESET)


class Timeout(State):
    """ Adds timeout functionality to a state. Timeouts are handled model-specific.
    Attributes:
        timeout (float): Seconds after which a timeout function should be called.
        on_timeout (list): Functions to call when a timeout is triggered.
    """

    dynamic_methods = ['on_timeout']
    timer = None
    timer_event_data = None

    def __init__(self, *args, **kwargs):
        """
        Args:
            **kwargs: If kwargs contain 'timeout', assign the float value to self.timeout. If timeout
                is set, 'on_timeout' needs to be passed with kwargs as well or an AttributeError will
                be thrown. If timeout is not passed or equal 0.
        """
        self.timeout = kwargs.pop('timeout', 0)
        self._on_timeout = None
        if self.timeout > 0:
            try:
                self.on_timeout = kwargs.pop('on_timeout')
            except KeyError:
                raise AttributeError("Timeout state requires 'on_timeout' when timeout is set.")
        else:
            self._on_timeout = kwargs.pop('on_timeout', [])
        self.runner = {}
        super(Timeout, self).__init__(*args, **kwargs)

    def enter(self, event_data):
        """ Extends `transitions.core.State.enter` by starting a timeout timer for the current model
            when the state is entered and self.timeout is larger than 0.
        """
        if self.timeout > 0:
            self.timer_event_data = event_data
            self.timer = self.start_timer(event_data)
            self.runner[id(event_data.model)] = self.timer

        super(Timeout, self).enter(event_data)

    def exit(self, event_data):
        """ Extends `transitions.core.State.exit` by canceling a timer for the current model. """
        self.stop_timer()
        super(Timeout, self).exit(event_data)

    def _process_timeout(self, event_data):
        if event_data.machine.print_timeout:
            print(Fore.YELLOW + '[!] State timeout')
        for callback in self.on_timeout:
            event_data.machine.callback(callback, event_data)

    def start_timer(self, event_data):
        timer = Timer(self.timeout, self._process_timeout, args=(event_data,))
        timer.setDaemon(True)
        timer.start()
        return timer

    def reset_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = self.start_timer(self.timer_event_data)
            self.runner[id(self.timer_event_data.model)] = self.timer

    def stop_timer(self):
        if self.timer:
            self.timer.cancel()

    @property
    def on_timeout(self):
        """ List of strings and callables to be called when the state timeouts. """
        return self._on_timeout

    @on_timeout.setter
    def on_timeout(self, value):
        """ Listifies passed values and assigns them to on_timeout."""
        self._on_timeout = listify(value)


class CustomNestedGraphTransition(TransitionGraphSupport, NestedTransition):
    """
        A transition type to be used with (subclasses of) `HierarchicalGraphMachine` and
        `LockedHierarchicalGraphMachine`.
    """

    def _change_state(self, event_data):
        event_data.machine.source = self.source
        event_data.machine.destination = self.dest
        if event_data.machine.print_transitions:
            print(Fore.BLUE + 'Transition:' + Fore.LIGHTCYAN_EX + self.source + Fore.BLUE +
                  ' ---> ' + Fore.LIGHTCYAN_EX + self.dest)
        super(CustomNestedGraphTransition, self)._change_state(event_data)


def creat_log_dirs(model_name):
    # Create target Directory if don't exist
    def verify_and_create(path):
        if not os.path.exists(path):
            os.mkdir(path)

    verify_and_create('logs')
    verify_and_create('logs/' + model_name)
    verify_and_create('logs/' + model_name + '/pcap')
    verify_and_create('logs/' + model_name + '/csv')
    verify_and_create('logs/' + model_name + '/monitor_serial')
    verify_and_create('logs/' + model_name + '/sessions')
    verify_and_create('logs/' + model_name + '/anomalies')


@add_state_features(Tags, Timeout)
class GreyhoundStateMachine(HierarchicalGraphMachine):
    transition_cls = CustomNestedGraphTransition
    # State machine variables
    model_name = None
    config_file = None
    idle_state = None  # type: str 
    enable_webserver = False
    file_count = 0
    print_transitions = False
    print_timeout = False
    source = None
    destination = None
    pcap_session_packets = []
    pcap_anomaly_packets = []
    pcap_anomaly_packets_number = 0

    def __init__(self, *args, **kwargs):

        self.model_name = inspect.currentframe().f_back.f_code.co_filename.split('/')[-1].split('.py')[0]
        creat_log_dirs(self.model_name)
        fitness.model_name = self.model_name

        self.idle_state = kwargs.pop('idle_state', '')
        self.enable_webserver = kwargs.pop('enable_webserver', False)

        if self.enable_webserver:
            kwargs['after_state_change'] = send_graph

        self.print_transitions = kwargs.pop('print_transitions', False)
        self.print_timeout = kwargs.pop('print_timeout', False)

        kwargs['title'] = ""
        kwargs['show_auto_transitions'] = False
        kwargs['model'] = inspect.currentframe().f_back.f_locals['self']

        # TODO: save stdout along with logs
        # sys.stdout = custom_print

        Packet.fuzzed = False  # Monkeypatch Packet class

        super(GreyhoundStateMachine, self).__init__(*args, **kwargs)

        model = kwargs['model']
        if self.enable_webserver:
            start_webserver(model)

    def add_packets(self, pkt):
        self.pcap_session_packets.append(pkt)
        self.pcap_anomaly_packets.append(pkt)
        self.pcap_anomaly_packets_number += 1

        # print('2: ' + str(pkt.fuzzed))

    def save_packets(self):
        self.file_count += 1

        def save_file_thread():
            try:
                temp_pkts = self.pcap_session_packets
                wrpcap('logs/' + self.model_name + '/sessions/session_' + str(self.file_count), temp_pkts)
            except:
                pass
            self.pcap_session_packets = None
            self.pcap_session_packets = []


            # temp_pkts = self.pcap_session_packets
            # wrpcap('logs/' + self.model_name + '/sessions/session_' + str(self.file_count), temp_pkts)

        Thread(target=save_file_thread).start()

    def save_anomaly_packets(self, anomaly_name):

        def save_file_thread():
            try:
                temp_pkts = self.pcap_anomaly_packets
                wrpcap('logs/' + self.model_name + '/anomalies/' + anomaly_name + '_' + str(self.file_count), temp_pkts)
            except:
                pass
            self.pcap_anomaly_packets_number = 0
            self.pcap_anomaly_packets = None
            self.pcap_anomaly_packets = []

        Thread(target=save_file_thread).start()

    def report_anomaly(self, msg=None, pkt=None):
        message = 'ANOMALY detected in state ' + self.model.state
        if msg:
            message = msg + '\n' + message
        print(Fore.RED + '[ANOMALY] ' + message)
        fitness.AnomalyDetected(self.model.state, pkt, message)
        send_vulnerability(fitness.IssueCounter, message, error=False)  # Inform user interface
        self.save_anomaly_packets('anomaly')

    def report_crash(self):
        message = 'CRASH detected in state ' + self.model.state
        print(Fore.RED + '[CRASH] ' + message)
        fitness.AnomalyDetected(self.model.state, None, message)
        send_vulnerability(fitness.IssueCounter, message, error=True)  # Inform user interface
        self.save_anomaly_packets('crash')

    def reset_state_timeout(self):
        state = self.get_state(self.model.state)
        if isinstance(state, Timeout):
            state.reset_timer()

    def reset_machine(self):
        func = getattr(self.model, 'to_' + self.idle_state)
        func()
