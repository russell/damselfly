#!/usr/bin/python

# Damselfly
#
# Copyright (c) 2014 Russell Sim <russell.sim@gmail.com.au>
# Copyright (c) 2013 Tristen Hayfield
#
# Damselfly is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Damselfly is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Damselfly.  If not, see <http://www.gnu.org/licenses/>.

import ConfigParser
import json
import logging
import os
import re
import subprocess
import sys
import time

import psutil
import ewmh
import Xlib.Xutil
import Xlib.Xatom
from twisted.internet import protocol, reactor, utils
from twisted.protocols.basic import LineReceiver


__version__ = '2013-09-30'
__identifier__ = 'DamselflyServer v. ' + __version__

# load config
config = ConfigParser.SafeConfigParser()

if config.read(os.path.expanduser('~/.damselfly.cfg')) == []:
    raise Exception("Failed to find or parse config file: " + os.path.expanduser(
        '~/.damselfly.cfg') + "\nPlease add a config file and restart the server.")

log_level = config.get("logging", "level").lower()

loglevels = {'debug': logging.DEBUG,
             'info': logging.INFO,
             'warning': logging.WARNING,
             'error': logging.ERROR}

assert log_level in loglevels, "%s no in %s" % (log_level, loglevels.keys())

try:
    # Will fail if logging_enabled isn't defined
    if logging_enabled:
        pass
except:
    root = logging.getLogger()
    root.setLevel(loglevels[log_level])

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(loglevels[log_level])
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)
    logging_enabled = True

LOG = logging.getLogger('DamselflyServer')

LOG.info(__identifier__)

done = False
connected = False

# here there be dragons: re's for parsing key commands
prekey = re.compile(
    "^ *(?:([acswm]+)-)?([a-zA-Z0-9]+)(?:[/]([0-9]+(?=:[0-9]+)))?(?:[:]([0-9]+))?(?:[/]([0-9]+))? *$")
prekeyp = re.compile(
    "^ *(?:([acswm]+)-)?([a-zA-Z0-9]+)(?:[:])(up|down)(?:[/]([0-9]+))? *$")

# re's for parsing mouse commands
premousemove = re.compile(
    "^ *(?:\( *(-?[0-9]+|-?(?:0?\.[0-9]+|1\.0)) *, *(-?[0-9]+|-?(?:0?\.[0-9]+|1\.0)) *\)|\[ *(-?[0-9]+|-?(?:0?\.[0-9]+|1\.0)) *, *(-?[0-9]+|-?(?:0?\.[0-9]+|1\.0)) *\]|< *(-?[0-9]+) *, *(-?[0-9]+) *>) *$")
premousepress = re.compile(
    "^ *(left|middle|wheel (?:up|down)|right)(?::([0-3]))?(?:/([0-9]+))? *$")
premousehr = re.compile(
    "^ *(left|middle|wheel (?:up|down)|right):(hold|release)(?:/([0-9]+))? *$")
premousesep = re.compile(" *,(?![- .0-9]*[])>])")


#--clearmodifiers
keySymDict = {
    'a': 'a',
    'b': 'b',
    'c': 'c',
    'd': 'd',
    'e': 'e',
    'f': 'f',
    'g': 'g',
    'h': 'h',
    'i': 'i',
    'j': 'j',
    'k': 'k',
    'l': 'l',
    'm': 'm',
    'n': 'n',
    'o': 'o',
    'p': 'p',
    'q': 'q',
    'r': 'r',
    's': 's',
    't': 't',
    'u': 'u',
    'v': 'v',
    'w': 'w',
    'x': 'x',
    'y': 'y',
    'z': 'z',
    'A': 'A',
    'B': 'B',
    'C': 'C',
    'D': 'D',
    'E': 'E',
    'F': 'F',
    'G': 'G',
    'H': 'H',
    'I': 'I',
    'J': 'J',
    'K': 'K',
    'L': 'L',
    'M': 'M',
    'N': 'N',
    'O': 'O',
    'P': 'P',
    'Q': 'Q',
    'R': 'R',
    'S': 'S',
    'T': 'T',
    'U': 'U',
    'V': 'V',
    'W': 'W',
    'X': 'X',
    'Y': 'Y',
    'Z': 'Z',
    '0': '0',
    '1': '1',
    '2': '2',
    '3': '3',
    '4': '4',
    '5': '5',
    '6': '6',
    '7': '7',
    '8': '8',
    '9': '9',
    ' ': 'space',
    '_': 'underscore',
    '.': 'period',
    ',': 'comma',
    '!': 'exclam',
    '"': 'quotedbl',
    '#': 'numbersign',
    '$': 'dollar',
    '%': 'percent',
    '&': 'ampersand',
    "'": 'apostrophe',
    '(': 'parenleft',
    ')': 'parenright',
    '*': 'asterisk',
    '+': 'plus',
    '-': 'minus',
    '/': 'slash',
    ':': 'colon',
    ';': 'semicolon',
    '<': 'less',
    '=': 'equal',
    '>': 'greater',
    '?': 'question',
    '@': 'at',
    '[': 'bracketleft',
    ']': 'bracketright',
    '^': 'asciicircum',
    '`': 'grave',
    '{': 'braceleft',
    '|': 'bar',
    '}': 'braceright',
    '~': 'asciitilde',
    'backslash': 'backslash',
}

keyModDict = {
    'a': 'alt',
    'c': 'ctrl',
    's': 'shift',
    'w': 'super',
    'm': 'meta',
}

keyDirDict = {
    'up': 'keyup',
    'down': 'keydown',
}

keyNameDict = {
    'a': 'a',
    'b': 'b',
    'c': 'c',
    'd': 'd',
    'e': 'e',
    'f': 'f',
    'g': 'g',
    'h': 'h',
    'i': 'i',
    'j': 'j',
    'k': 'k',
    'l': 'l',
    'm': 'm',
    'n': 'n',
    'o': 'o',
    'p': 'p',
    'q': 'q',
    'r': 'r',
    's': 's',
    't': 't',
    'u': 'u',
    'v': 'v',
    'w': 'w',
    'x': 'x',
    'y': 'y',
    'z': 'z',
    'A': 'A',
    'B': 'B',
    'C': 'C',
    'D': 'D',
    'E': 'E',
    'F': 'F',
    'G': 'G',
    'H': 'H',
    'I': 'I',
    'J': 'J',
    'K': 'K',
    'L': 'L',
    'M': 'M',
    'N': 'N',
    'O': 'O',
    'P': 'P',
    'Q': 'Q',
    'R': 'R',
    'S': 'S',
    'T': 'T',
    'U': 'U',
    'V': 'V',
    'W': 'W',
    'X': 'X',
    'Y': 'Y',
    'Z': 'Z',
    '0': '0',
    '1': '1',
    '2': '2',
    '3': '3',
    '4': '4',
    '5': '5',
    '6': '6',
    '7': '7',
    '8': '8',
    '9': '9',
    'left': 'Left',
    'right': 'Right',
    'up': 'Up',
    'down': 'Down',
    'pgup': 'Page_Up',
    'pgdown': 'Page_Down',
    'home': 'Home',
    'end': 'End',
    'space': 'space',
    'tab': 'Tab',
    'enter': 'Return',
    'backspace': 'BackSpace',
    'del': 'Delete',
    'insert': 'Insert',
    'ampersand': 'ampersand',
    'apostrophe': 'apostrophe',
    'asterisk': 'asterisk',
    'at': 'at',
    'backslash': 'backslash',
    'colon': 'colon',
    'comma': 'comma',
    'dollar': 'dollar',
    'backtick': 'grave',
    'bar': 'bar',
    'caret': 'asciicircum',
    'dot': 'period',
    'dquote': 'quotedbl',
    'equal': 'equal',
    'minus': 'minus',
    'percent': 'percent',
    'plus': 'plus',
    'question': 'question',
    'semicolon': 'semicolon',
    'slash': 'slash',
    'underscore': 'underscore',
    'escape': 'Escape',
    'exclamation': 'exclam',
    'hash': 'numbersign',
    'hyphen': 'minus',
    'squote': 'apostrophe',
    'tilde': 'asciitilde',
    'f1': 'F1',
    'f2': 'F2',
    'f3': 'F3',
    'f4': 'F4',
    'f5': 'F5',
    'f6': 'F6',
    'f7': 'F7',
    'f8': 'F8',
    'f9': 'F9',
    'f10': 'F10',
    'f11': 'F11',
    'f12': 'F12',
    'f13': 'F13',
    'f14': 'F14',
    'f15': 'F15',
    'f16': 'F16',
    'f17': 'F17',
    'f18': 'F18',
    'f19': 'F19',
    'f20': 'F20',
    'f21': 'F21',
    'f22': 'F22',
    'f23': 'F23',
    'f24': 'F24',
    'ctrl': 'ctrl',
    'alt': 'alt',
    'shift': 'shift',
    'langle': 'less',
    'lbrace': 'braceleft',
    'lbracket': 'bracketleft',
    'lparen': 'parenleft',
    'rangle': 'greater',
    'rbrace': 'braceright',
    'rbracket': 'bracketright',
    'rparen': 'parenright',
    'apps': 'meta',
    'win': 'super',
    'np0': 'KP_0',
    'np1': 'KP_1',
    'np2': 'KP_2',
    'np3': 'KP_3',
    'np4': 'KP_4',
    'np5': 'KP_5',
    'np6': 'KP_6',
    'np7': 'KP_7',
    'np8': 'KP_8',
    'np9': 'KP_9',
    'npadd': 'KP_Add',
    'npdec': 'KP_Decimal',
    'npdiv': 'KP_Divide',
    'npmul': 'KP_Multiply',
    'npsep': 'KP_Separator',
    'npsub': 'KP_Subtract',
}

mouseButtonDict = {
    'left': '1',
    'middle': '2',
    'right': '3',
    'wheel up': '4',
    'wheel down': '5',
}

mouseHRDict = {
    'down': 'mousedown',
    'up': 'mouseup',
}


class ParseFailure(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class InvalidArgs(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class WindowNotFound(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def parseStr2xdotool(string):
    skip = False
    js = ''

    if string[0] == '\\':
        skip = True
        ns = []
    elif string[0] not in keySymDict:
        raise ParseFailure('invalid character: "' + string[0] + '" in string')
    else:
        ns = [keySymDict[string[0]]]

    if len(string) > 1:
        for ch in string[1:]:
            if ch == ' ':
                skip = False
                if js == 'backslash':
                    ns.append(keySymDict[js])
                js = ''
            elif ch == '\\':
                skip = True
                continue

            if skip:
                js += ch
                continue

            if ch not in keySymDict:
                raise ParseFailure('invalid character: "' + ch + '" in string')
            ns.append(keySymDict[ch])

        if skip and js == 'backslash':
            ns.append(keySymDict[js])

    return ns

# need to parse:
# either: [modifiers -] keyname [/ innerpause] [: repeat] [/ outerpause]
# or: [modifiers -] keyname : direction [/ outerpause]
# PARSES A SINGLE KEY


def parseKey2xdotool(kexp):
    babby = prekey.match(kexp)
    cmd = []
    op = None
    bc = 0
    tc = ''

    # does babby conform to: [modifiers -] keyname [/ innerpause] [: repeat]
    # [/ outerpause] ?
    if babby:
        # modifiers
        bg = babby.groups()
        if bg[0]:
            for ch in bg[0][:]:
                if ch in tc:
                    raise ParseFailure(
                        'Double modifier in expression: ' + str(bg[0]))
                tc += bc * '+' + keyModDict[ch]
                bc = 1
        # key to send
        if bg[1] not in keyNameDict:
            raise ParseFailure('invalid key name in expression: ' + str(bg[1]))

        tc += bc * '+' + keyNameDict[bg[1]]

        cmd.append(tc)

        cmd.insert(0, '-delay')
        if bg[2]:
            cmd.insert(1, bg[2])
        else:
            cmd.insert(1, '1')

        if bg[3]:
            cmd.extend((int(bg[3]) - 1) * [tc])

        cmd.insert(0, 'key')
        cmd.insert(1, '-clearmodifiers')

        if bg[4]:
            op = float(bg[4]) / 1000.0
    else:
        # does babby conform to: [modifiers -] keyname : direction [/
        # outerpause] ?
        babby = prekeyp.match(kexp)

        if babby is None:
            raise ParseFailure('invalid key expression: ' + kexp)

        bg = babby.groups()
        if bg[0]:
            for ch in bg[0][:]:
                if ch in tc:
                    raise ParseFailure(
                        'Double modifier in expression: ' + str(bg[0]))
                tc += bc * '+' + keyModDict[ch]
                bc = 1
        # key to send
        if bg[1] not in keyNameDict:
            raise ParseFailure('invalid key name in expression: ' + bg[1])

        tc += bc * '+' + keyNameDict[bg[1]]

        cmd.append(tc)

        cmd.insert(0, bg[2])
        cmd.insert(1, '-clearmodifiers')

        if bg[3]:
            op = float(bg[3]) / 1000.0

    return [cmd, op]

# need to parse:
# either: movement (3*2 types), or clicks, or presses
# PARSES A SINGLE mouse command


def parseMouse2xdotool(wm, kexp):
    babby = premousemove.match(kexp)
    cmd = []
    op = None

    # does babby move?
    if babby:
        ic = None
        wh = None
        mref = None

        bg = babby.groups()
        # 0,1 - parentheses - window-relative
        # 2,3 - brackets - absolute
        # 4,5 - angle brackets - mouse-relative
        if bg[0]:
            cmd = ["getactivewindow", "mousemove", "--window", "%1"]
            ic = 0
            mref = "active"
        elif bg[2]:
            cmd = ["mousemove"]
            ic = 2
            mref = "root"
        else:
            ic = 4
            cmd = ["mousemove_relative"]
            mref = "mouse"

        # tests for presence of - or .
        ix = bg[ic].isdigit()
        iy = bg[ic + 1].isdigit()

        if not (ix and iy):
            wh = window_size(wm, mref)

        # test for integer coords
        if bg[ic].find('.') == -1:
            x = int(bg[ic])
            if x < 0:
                x += wh[0]
        else:
            x = float(bg[ic])
            if x < 0.0:
                x += 1.0
            x = int(round(x * (wh[0] - 1)))

        cmd.append(str(x))

        if bg[ic + 1].find('.') == -1:
            y = int(bg[ic + 1])
            if y < 0:
                y += wh[1]
        else:
            y = float(bg[ic + 1])
            if y < 0.0:
                y += 1.0
            y = int(round(y * (wh[1] - 1)))

        cmd.append(str(y))

    else:
        # does babby click
        babby = premousepress.match(kexp)

        if babby:
            bg = babby.groups()
            cmd = ["click"]
            if bg[2]:
                op = float(bg[2]) / 100.0

            if bg[1]:
                if int(bg[1]) == 0:
                    cmd = ["sleep", "0"]
                    return [cmd, op]
                else:
                    cmd.extend(["--repeat", bg[1]])

            cmd.append(mouseButtonDict[bg[0]])
        else:
            babby = premousehr.match(kexp)

            if babby is None:
                raise ParseFailure('invalid mouse expression: ' + kexp)

            bg = babby.groups()

            cmd = [mouseHRDict[bg[1]], mouseButtonDict[bg[0]]]

            if bg[2]:
                op = float(bg[2]) / 100.0

    return [cmd, op]


def window_size(wm, id="root"):
    if id == "root":
        return list(wm.getDesktopGeometry())
    elif id == "active":
        window = wm.getActiveWindow()
    else:
        window = self.wm.display.create_resource_object('window',
                                                        int(value))
    data = window.get_geometry()._data
    return [data['width'], data['height']]


def window_executable(wm, window):
    pid = window.get_full_property(wm.display.intern_atom('_NET_WM_PID'),
                                   Xlib.Xatom.CARDINAL).value[0]
    process = psutil.Process(pid)
    return process.cmdline()


class LoggingProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, name):
        self.name = name
        self.data = ""

    def connectionMade(self):
        LOG.info("%s: Started..." % self.name)

    def outReceived(self, data):
        for line in data.split("\n"):
            LOG.info("%s: %s" % (self.name, data))

    def errReceived(self, data):
        LOG.info(data)

    def processExited(self, reason):
        LOG.info("%s: processExited, status %d"
                 % (self.name, reason.value.exitCode))

    def processEnded(self, reason):
        LOG.info("%s: processEnded, status %d"
                 % (self.name, reason.value.exitCode))


class DamselflyServer(LineReceiver):

    stop_processing = True

    def __init__(self):
        self.wm = ewmh.EWMH()

    def sendMsg(self, **kwargs):
        self.sendLine(json.dumps(kwargs))

    def connectionMade(self):
        self.handle_cast_sendNotification("Damselfly connected")
        LOG.info("Connection made.")

    def connectionLost(self, reason):
        self.handle_cast_sendNotification("Damselfly connection lost")
        LOG.info("Connection lost.")

    def lineReceived(self, line):
        message = json.loads(line)

        if 'call' in message:
            try:
                command = 'handle_call_' + message['call']
                del message['call']
                LOG.debug("Received command: %s, %s " % (command, message))
                getattr(self, command)(**message)
            except Exception as e:
                LOG.exception("Failed to process message.")
                self.sendMsg(error=str(e))
        elif 'cast' in message:
            try:
                command = 'handle_cast_' + message['cast']
                del message['cast']
                LOG.debug("Received command: %s, %s " % (command, message))
                getattr(self, command)(**message)
            except Exception as e:
                LOG.exception("Failed to process message.")
        else:
            LOG.warning("Unknown message: %s" % str(message))

    def handle_call_handshake(self, identity):
        LOG.info("Connected to client %s" % identity)
        self.sendMsg(message="Connected", identity=__identifier__)

    def handle_call_getXCtx(self):
        window = self.wm.getActiveWindow()
        self.sendMsg(window_name=window.get_wm_name(),
                     window_class=str(window.get_wm_class()),
                     window_id=window.id,
                     executable=window_executable(self.wm, window))

    def handle_cast_sendXText(self, text):
        cmd = ["xdotool", "key", "-clearmodifiers"]
        res = parseStr2xdotool(text)
        if res:
            cmd.extend(res)
            subprocess.check_call(cmd)

    def handle_cast_sendXKeys(self, keys):
        keys = keys.split(',')

        for key in keys:
            cmd = ["xdotool"]
            tcmd = parseKey2xdotool(key)
            cmd.extend(tcmd[0])
            subprocess.check_call(cmd)
            if tcmd[1]:
                time.sleep(tcmd[1])

    def handle_cast_sendXMouse(self, moves):
        moves = premousesep.split(moves)

        for move in moves:
            cmd = ["xdotool"]
            tcmd = parseMouse2xdotool(self.wm, move)
            cmd.extend(tcmd[0])
            subprocess.check_call(cmd)
            if tcmd[1]:
                time.sleep(tcmd[1])

    def handle_cast_sendNotification(self, message):
        command = ["notify-send", "-t", "1000", message]
        reactor.spawnProcess(LoggingProcessProtocol("notify-send"),
                             command[0], command,
                             env=os.environ)

    def find_window(self, executable='', title=''):
        for window in self.wm.getClientList():
            cmdline = " ".join(window_executable(self.wm, window))
            if executable not in cmdline and \
               title not in window.get_wm_name().lower() and \
               title not in str(window.get_wm_class()).lower():
                continue
            return window

    def handle_cast_hideXWindowById(self, id):
        actions = self.wm.getWmAllowedActions(self.getActiveWindow(), str=True)
        if '_NET_WM_ACTION_MINIMIZE' not in actions:
            self.handle_cast_sendNotification("WM doesn't support Minimising.")
            return
        window = self.wm.getActiveWindow()
        window.set_wm_state(state=Xlib.Xutil.IconicState, icon=0)
        self.wm.display.flush()

    def handle_cast_hideXWindow(self, title):
        actions = self.wm.getWmAllowedActions(self.getActiveWindow(), str=True)
        if '_NET_WM_ACTION_MINIMIZE' not in actions:
            self.handle_cast_sendNotification("WM doesn't support Minimising.")
            return
        window = self.find_window(title=title)
        window.set_wm_state(state=Xlib.Xutil.IconicState, icon=0)
        self.wm.display.flush()

    def handle_cast_focusXWindowById(self, id):
        window = self.wm.display.create_resource_object('window',
                                                        int(value))
        self.wm.setActiveWindow(window)
        self.wm.display.flush()
        return True

    def handle_cast_focusXWindow(self, executable='', title=''):
        title = title.lower()
        assert executable and title, "Missing executable and title"
        window = self.find_window(executable, title)
        if not window:
            raise WindowNotFound('Could not activate window: ' + title)
        self.wm.setActiveWindow(window)
        self.wm.display.flush()
        return window

    def handle_call_waitXWindow(self, title='', executable='', timeout=1.0):
        window = handle_cast_focusXWindow(executable=executable, title=title)
        start_time = time.time()
        while self.wm.getActiveWindow() != window.id:
            time.sleep(0.1)
            if time >= start_time:
                raise Exception("Timed out.")
        self.handle_call_getXCtx()

    def handle_cast_bringXApp(self, executable):
        # XXX Using [0] is a bit vague.
        window = self.find_window(executable[0])
        if window:
            self.wm.setActiveWindow(window)
            self.wm.display.flush()
        else:
            self.handle_cast_startXApp(executable)

    def handle_cast_startXApp(self, executable, cwd=None):
        reactor.spawnProcess(LoggingProcessProtocol(executable[0]),
                             executable[0], executable,
                             env=os.environ,
                             path=cwd or os.getcwd())

    def handle_cast_sendEmacs(self, lisp):
        command = ["emacsclient", "--eval"]
        command.append("(with-current-buffer"
                       " (window-buffer"
                       "  (frame-selected-window"
                       "   (selected-frame))) %s)" % lisp)
        reactor.spawnProcess(LoggingProcessProtocol('emacsclient'),
                             command[0], command,
                             env=os.environ)

    def handle_call_sendEmacs(self, lisp):
        command = ["--eval"]
        command.append("(with-current-buffer"
                       " (window-buffer"
                       "  (frame-selected-window"
                       "   (selected-frame))) %s)" % lisp)
        d = utils.getProcessOutput("emacsclient", command,
                                   env=os.environ)
        d.addCallback(lambda x: self.sendMsg(major_mode=x.strip()))

    def handle_cast_sendStumpWM(self, arguments):
        command = ["stumpish"] + arguments
        reactor.spawnProcess(LoggingProcessProtocol(command[0]),
                             command[0], command,
                             env=os.environ)


class DamselflyFactory(protocol.Factory):

    def buildProtocol(self, addr):
        return DamselflyServer()


if __name__ == "__main__":
    reactor.listenTCP(8123, DamselflyFactory())
    reactor.run()
