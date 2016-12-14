from os import path
import os
import socket
import atexit
import pickle
import select

class _UDS(object):
    SOCK_FILE = path.join(path.dirname(__file__), 'pikaball.socket')
    BUFF_SIZE = 256

    def __init__(self, server):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        def rm(f):
            try:
                os.remove(f)
            except FileNotFoundError:
                pass

        @atexit.register
        def cleaner():
            sock.close()
            rm(self.SOCK_FILE)

        if server:
            rm(self.SOCK_FILE)
            sock.bind(self.SOCK_FILE)
            sock.listen(1)
            self.conn, _ = sock.accept()
        else:
            sock.connect(self.SOCK_FILE)
            self.conn = sock

    def incoming(self):
        sl, _, _ = select.select([self.conn], [], [], 0.001)
        return bool(sl)

    def send(self, obj):
        payload = pickle.dumps(obj)
        size = len(payload)
        assert size < self.BUFF_SIZE
        bsent = self.conn.send(payload)
        assert bsent == size

    def recv(self):
        bs = self.conn.recv(self.BUFF_SIZE)
        return pickle.loads(bs)

class _AgentSocket(_UDS):
    send_action = _UDS.send
    recv_observation = _UDS.recv
    observation_ready = _UDS.incoming
    def __init__(self):
        print('Connecting to environment...')
        self.sock = _UDS.__init__(self, server=False)
        print('Connected')

class _EnvironmentSocket(_UDS):
    send_observation = _UDS.send
    recv_action = _UDS.recv
    def __init__(self):
        print('Waiting for agent...')
        self.sock = _UDS.__init__(self, server=True)
        print('Connected')


if __name__ == '__main__':
    from gdb import parse_and_eval as pae
    from math import copysign
    import gdb
    import struct

    def loadaddrs(configs):
        addrs = {}
        class BP(gdb.Breakpoint):
            def __init__(self, ip, assignments, cond):
                gdb.Breakpoint.__init__(self, ip)
                self.silent = True
                # gdb.Breakpoint.condition does not prevent `stop`
                # from being called, so here we use our own attribute
                # so condition won't be checked twice
                self.cond = cond
                self.assignments = assignments

            def stop(self):
                if bool(pae(self.cond)):
                    for k, value_expr in self.assignments:
                        v = int(pae(value_expr))
                        addrs[k] = v
                        print('{0} @ 0x{1:08X}'.format(k, v))
                    self.enabled = False
                return False

        for ip, assignments, condition in configs:
            for k, _ in assignments:
                addrs[k] = None
            BP(ip, assignments, condition)

        return addrs

    bytes2int = int.from_bytes
    inferior = gdb.selected_inferior()
    writemem = inferior.write_memory
    readmem = inferior.read_memory
    def readshort(addr):
        return bytes2int(readmem(addr, 2), 'little')

    def agent_disconnected():
        print('Agent disconnected')
        gdb.execute('quit')

    class DecisionBreakpoint(gdb.Breakpoint):
        INIT_FRAME = [('LX',36),('LY',244),('BY',1),('RX',396),('RY',244)]
        #{'BX': 56, 'LS': 13, 'RS': 3, 'RY': 244, 'BY': 6, 'RX': 396, 'LX': 48, 'LY': 213}
        BREAK_ADDR = 0x00403D90

        def __init__(self, addrs):
            gdb.Breakpoint.__init__(self, '*%d' % self.BREAK_ADDR)
            self.silent = True
            self.addrs = addrs
            self.action = (-1, -1, -1)
            self.wait_init = True
            self.prev_ball = (-1, -1)
            self.socket = _EnvironmentSocket()

        def stop(self):
            try:
                frame = dict((k, readshort(a)) for k, a in self.addrs.items())
            except TypeError:
                # addrs not fully loaded yet
                return False

            if self.wait_init:
                self.wait_init = any(frame[k] != v for k, v in self.INIT_FRAME)

                if self.wait_init:
                    by = struct.pack('i', 300) # 300: below ground
                    writemem(self.addrs['BY'], by) # force ball below ground to end round
                    return False
                else:
                    # reset the scores
                    writemem(self.addrs['RS'], '\0')
                    writemem(self.addrs['LS'], '\0')
                    frame['RS'], frame['LS'] = 0, 0

                    # this is the correct initial ball position
                    self.prev_ball = (frame['BX'], 0)

                    while self.action is not None:
                        # agent needs to have sent a reset (None) action
                        # to observe first frame
                        self.action = self.socket.recv_action()

            # ball position from previous frame is the correct current ball position
            bx, by = frame['BX'], frame['BY']
            frame['BX'], frame['BY'] = self.prev_ball
            self.prev_ball = bx, by

            scorediff = frame['RS'] - frame['LS']
            reward = 0 if scorediff == 0 else copysign(1, scorediff)
            self.wait_init = terminal = reward != 0

            try:
                self.socket.send_observation((frame, reward, terminal))
                self.action = action = self.socket.recv_action()
            except (BrokenPipeError, ConnectionResetError, EOFError):
                agent_disconnected()

            if action:
                ss = [1 if a > 0 else -1 if a < 0 else 0 for a in action]
                bs = struct.pack('iii', *ss)
                base = int(pae('$eax')) + 0x10 # base of right player
                writemem(base, bs)
                #print('KEY (0x{:08X}): {}'.format(base, str(bs)))
            else:
                # agent resets environment
                self.wait_init = True

            return False

    gdb.execute('set print thread-events off')
    gdb.execute('set pagination off')
    gdb.execute('set confirm off')
    gdb.execute('handle SIGUSR1 nostop noprint')

    addrs = loadaddrs([
        # break at *0x004027B1, set value for LX to $esi+0xA8, and LY.. if *($esi+0xA8) < 216
        ('*0x004027B1', [('LX', '$esi+0xA8'), ('LY', '$esi+0xAC')], '*($esi+0xA8) < 216'),
        ('*0x004027B1', [('RX', '$esi+0xA8'), ('RY', '$esi+0xAC')], '*($esi+0xA8) > 216'),
        ('*0x00402EB4', [('BX', '$esi+0x30'), ('BY', '$esi+0x34')], '1'),
        ('*0x00403D4B', [('LS', '$esi+0x3C'), ('RS', '$esi+0x40')], '1')
    ])
    db = DecisionBreakpoint(addrs)
    gdb.execute('continue')

else:
    from itertools import product
    import numpy as np

    class _Object(object):
        def __init__(self, **attrs):
            for k, v in attrs.items():
                self.__setattr__(k, v)

    _ACTIONS = list(product([-1,0,1],[-1,0,1],[0,1]))

    # https://github.com/openai/gym/blob/master/gym/spaces/box.py
    observation_space = _Object(
        high = np.array([432.0, 323.0]*3),
        low = np.zeros(6),
        shape = lambda: (6,)
    )
    # https://github.com/openai/gym/blob/master/gym/spaces/discrete.py
    action_space = _Object(
        n = 18,
        labels = ['%s %s %s' % (' ><'[h], ' ∨∧'[v], ' N'[n]) for h, v, n in _ACTIONS]
    )

    _done = True
    _socket = _AgentSocket()

    def _observe():
        global _done
        frame, reward, terminal = _socket.recv_observation()
        observation = np.array([frame[k] for k in ['LX', 'LY', 'RX', 'RY', 'BX', 'BY']], dtype=np.float32)
        _done = terminal
        return observation, reward, terminal

    def reset():
        _socket.send_action(None)
        observation, _, _ = _observe()
        return observation

    def step(action):
        assert not _done, 'step called after end of episode before resetting'
        a = _ACTIONS[action]
        _socket.send_action(a)
        observation, reward, done = _observe()
        return observation, reward, done, {}
