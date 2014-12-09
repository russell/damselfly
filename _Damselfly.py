# Damselfly
#
# Copyright (C) 2014 Russell Sim <russell.sim@gmail.com>
# Copyright (C) 2013 Tristen Hayfield
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

import logging
import sys
import re
import socket
import json
import time

from dragonfly import (Grammar, Rule, MappingRule, CompoundRule,
                       Dictation, IntegerRef, Context, ActionBase,
                       Choice)

from dragonfly.actions.action_base import DynStrActionBase

__version__ = '2013-09-30'
__identifier__ = __name__[1:] + ' v. ' + __version__


try:
    # try and unload if it's defined
    grammar.unload()  # NOQA
except:
    pass

try:
    # Will fail if logging enabled isn't defined
    if logging_enabled:  # NOQA
        pass
except:
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)
    logging_enabled = True

LOG = logging.getLogger(__name__[1:])

LOG.info("Loaded " + __identifier__)

connected = False
windowCache = {}

servers = {"sparky": ("localhost", 8123),
           "kieran": ("kieran.dev", 8123)}

current_server = "sparky"
previous_server = "kieran"

# Create a socket (SOCK_STREAM means a TCP socket)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def connect(host, port):
    global sock, connected
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        # Connect to server and send data
        LOG.info('Opening connection to server. %s:%s' % (host, port))
        sock.connect((host, port))
        connected = True
        server_id = call("handshake", identity=__identifier__)
        LOG.info('Connected. %s' % server_id)
    except:
        LOG.exception("Failed to connect.")
        disconnect()


def sendMsg(**kwargs):
    if connected is not True:
        connect(*servers[current_server])
    try:
        data = json.dumps(kwargs)
        LOG.info("Sending %s" % data)
        sock.sendall(data + "\r\n")
    except:
        LOG.exception("Failed to send.")
        disconnect()
        raise

buffer = ""


def recvMsg():
    global buffer
    start = time.time()
    # TODO needs to have a timeout
    LOG.info('waiting for response.')
    while True:
        if connected is not True:
            raise Exception("Trying to receive from disconnected socket.")
        buffer = buffer + sock.recv(1024)
        if buffer.find('\n') > -1:
            messages = buffer.split('\n', 1)
            if len(messages) > 1:
                buffer = messages[1]
            message = json.loads(messages[0])
            if 'error' in message:
                raise Exception(message['error'])
            return message
        if time.time() - start > 4:
            raise Exception("Timed out waiting for response")


def call(command, **kwargs):
    sendMsg(call=command, **kwargs)
    return recvMsg()


def cast(command, **kwargs):
    sendMsg(cast=command, **kwargs)


def disconnect():
    global connected

    sock.close()
    LOG.info('Disconnected')

    connected = False


class cache(object):
    """Cache With Timeout"""
    _cache = None
    _timeout = 0
    timeout = None

    def __init__(self, timeout=1):
        self.timeout = timeout

    def __call__(self, f):
        def func(*args, **kwargs):
            if (time.time() - self._timeout) > self.timeout:
                self._cache = f(*args, **kwargs)
                self._timeout = time.time()
            return self._cache
        func.func_name = f.func_name

        return func


@cache(1)
def getXCtx():
    if connected:
        LOG.info('Requesting X context.')
        msg = call('getXCtx')
        xctx = [msg.get('window_name', ''),
                msg.get('window_class', ''),
                msg.get('window_id', '')]
        LOG.info('response received: %s' % xctx)
        return xctx

# custom contexts


def reCmp(pattern, string):
    return pattern.search(string) is not None


def strCmp(sub, string):
    return sub in string


class XAppContext(Context):

    def __init__(self, wmname=None, wmclass=None, wid=None, usereg=False):
        self.wmname = wmname

        if wmclass is None:
            self.wmclass = wmname
            self.either = True
        else:
            self.wmclass = wmclass
            self.either = False

        self.wid = wid

        if usereg:
            self.myCmp = reCmp

            if self.wmname:
                self.wmname = re.compile(self.wmname)

            if self.wmclass:
                self.wmclass = re.compile(self.wmclass)

        else:
            self.myCmp = strCmp

        self.emptyCtx = (wmname is None) & (wmclass is None) & (wid is None)
        self._str = "name: " + \
            str(wmname) + ", " + "class: " + \
            str(wmclass) + ", " + "id: " + str(wid)

    def matches(self, executable, title, handle):
        if not connected:
            return False

        if self.emptyCtx:
            return True

        iMatch = True

        ctx = getXCtx()

        if self.either:
            iMatch &= self.myCmp(
                self.wmname, ctx[0]) | self.myCmp(self.wmclass, ctx[1])
        else:
            if self.wmname:
                iMatch &= self.myCmp(self.wmname, ctx[0])

            if self.wmclass:
                iMatch &= self.myCmp(self.wmclass, ctx[1])

        if self.wid:
            iMatch &= (ctx[2] == self.wid)

        return iMatch

# custom actions: prepare for the babbyscape


class FocusXWindow(DynStrActionBase):

    def __init__(self, spec, search=None, static=False):
        DynStrActionBase.__init__(self, spec=spec, static=static)
        if not search:
            self.search = 'any'
        else:
            self.search = str(search)

    def _execute_events(self, events):
        if (self.search == 'any') and (self._pspec in windowCache):
            return cast('focusXWindowById',
                        id=windowCache[self._pspec])
        else:
            return cast('focusXWindow',
                        mode=self.search,
                        name=str(self._pspec))

    def _parse_spec(self, spec):
        self._pspec = spec
        return self


class HideXWindow(DynStrActionBase):

    def __init__(self, spec=None, search=None, static=False):
        DynStrActionBase.__init__(
            self, spec=str(spec), static=(spec is None))
        if not search:
            self.search = 'any'
        else:
            self.search = str(search)

    def _execute_events(self, events):
        if (self.search == 'any') and (self._pspec in windowCache):
            return cast('hideXWindowById',
                        id=windowCache[self._pspec])
        else:
            return cast('hideXWindow',
                        title=str(self._pspec))

    def _parse_spec(self, spec):
        self._pspec = spec
        return self


class CacheXWindow(DynStrActionBase):

    def __init__(self, spec, static=False, forget=False):
        DynStrActionBase.__init__(self, spec=str(spec), static=static)
        self.search = 'id'
        self.forget = forget

    def _execute_events(self, events):
        global windowCache
        if not self.forget:
            xctx = getXCtx()
            if xctx:
                windowCache[self._pspec] = str(xctx[2])
            else:
                return False
        else:
            if self._pspec == 'all':
                windowCache = {}
            elif self._pspec in windowCache:
                del windowCache[self._pspec]
            else:
                return False

    def _parse_spec(self, spec):
        self._pspec = spec
        return self


class BringXApp(ActionBase):

    def __init__(self, *args, **kwargs):
        ActionBase.__init__(self)
        self.args = args
        self.kwargs = kwargs

    def _execute(self, data=None):
        return cast('bringXApp',
                    executable=self.args,
                    **self.kwargs)


class WaitXWindow(ActionBase):

    def __init__(self, title, executable, timeout=5.0):
        ActionBase.__init__(self)
        self.title = title
        self.executable = executable
        self.timeout = timeout

    def _execute(self, data=None):
        return call('waitXWindow',
                    title=self.title,
                    executable=self.executable,
                    timeout=self.timeout)


class StartXApp(ActionBase):

    def __init__(self, *args, **kwargs):
        ActionBase.__init__(self)
        self.args = args
        self.kwargs = kwargs

    def _execute(self, data=None):
        return cast('startXApp', executable=self.args, **self.kwargs)


class XKey(DynStrActionBase):

    def _execute_events(self, events):
        return cast('sendXKeys', keys=self._pspec)

    def _parse_spec(self, spec):
        self._pspec = spec
        return self


class XMouse(DynStrActionBase):

    def _execute_events(self, events):
        return cast('sendXMouse', moves=self._pspec)

    def _parse_spec(self, spec):
        self._pspec = spec
        return self


class XText(DynStrActionBase):

    def __init__(self, spec, static=False, space=True,
                 title=False, upper=False, lower=False, camel=False):
        DynStrActionBase.__init__(self, spec=str(spec), static=static)
        self.space = space
        self.title = title
        self.upper = upper
        self.lower = lower
        self.camel = camel

    def _parse_spec(self, spec):
        return spec

    def _mutate_text(self, text):
        if self.lower:
            text = text.lower()
        elif self.title:
            text = text.title()
        elif self.upper:
            text = text.upper()
        elif self.camel:
            text = text.title()
            text = text[:1].lower() + text[1:]

        if self.space is False:
            text = text.replace(' ', '')
        elif self.space is not True:
            text = text.replace(' ', self.space)
        return text

    def _mutate_data(self, data):
        return dict((k, self._mutate_text(v))
                    for k, v in data.iteritems())

    def _execute(self, data=None):
        if self._static:
            # If static, the events have already been parsed by the
            #  initialize() method.
            self._execute_events(self._events)

        else:
            # If not static, now is the time to build the dynamic spec,
            #  parse it, and execute the events.

            if not data:
                spec = self._spec
            else:
                try:
                    spec = self._spec % self._mutate_data(data)
                except KeyError:
                    self._log_exec.error("%s: Spec %r doesn't match data %r."
                                         % (self, self._spec, data))
                    return False

            self._log_exec.debug("%s: Parsing dynamic spec: %r"
                                 % (self, spec))
            events = self._parse_spec(spec)
            self._execute_events(events)

    def _execute_events(self, events):
        return cast('sendXText', text=events)


class DoNothing(ActionBase):
    _str = "DoNothing"

    def __init__(self, message='Recognition event consumed.'):
        self.message = message

    def _execute(self, data=None):
        LOG.debug("DoNothing: %s" % self.message)


#
# Emacs
#

class EmacsEval(ActionBase):

    def __init__(self, lisp=""):
        super(EmacsEval, self).__init__()
        self.lisp = lisp

    def _execute(self, data=None):
        return cast('sendEmacs', lisp=self.lisp % data)


class EmacsICmd(EmacsEval):

    def __init__(self, command="", prefix=False):
        super(EmacsICmd, self).__init__("(call-interactively '%s)" % command)
        self.prefix = False

    def _execute(self, data=None):
        lisp = self.lisp
        args = ""
        if self.prefix is True and 'n' in data:
            args = "(setq current-prefix-arg '(%s))" % data['n']
        lisp = "(progn %s %s (undo-boundary))" % (args, self.lisp)
        return cast('sendEmacs', lisp=lisp % data)


class EmacsIKey(XText):

    def __init__(self, spec, static=False):
        super(EmacsIKey, self).__init__(str(spec), static)

    def _parse_spec(self, spec):
        self._pspec = spec
        return self

    def _execute_events(self, events):
        lisp = ("(progn"
                " (execute-kbd-macro (read-kbd-macro \"%s\"))"
                " (undo-boundary))" % (self._pspec))
        return cast('sendEmacs', lisp=lisp)


class EmacsIText(EmacsIKey):

    def __init__(self, spec, static=False, space=True,
                 title=False, upper=False, lower=False, camel=False):
        super(EmacsIText, self).__init__(spec, static)
        self.space = space
        self.title = title
        self.upper = upper
        self.lower = lower
        self.camel = camel

    def _execute_events(self, events):
        lisp = ("(progn"
                " (execute-kbd-macro \"%s\")"
                " (undo-boundary))" % events)
        return cast('sendEmacs', lisp=lisp)


class EmacsIProgn(EmacsEval):
    def __init__(self, forms=""):
        super(EmacsIProgn, self).__init__(
            "(call-interactively '(lambda () (interactive) %s))" % forms)


class EmacsContext(XAppContext):
    _cache = cache(1)

    def __init__(self, wmname=None, wmclass=None, wid=None,
                 usereg=False, major_mode=''):
        super(EmacsContext, self).__init__(wmname=wmname, wmclass=wmclass,
                                           wid=wid, usereg=usereg)
        self.usereg = usereg
        if usereg:
            self.major_mode = re.compile(major_mode)
        else:
            self.major_mode = major_mode

    def matches(self, executable, title, handle):
        if not super(EmacsContext, self).matches(executable, title, handle):
            return False
        major_mode = self._cache(call)('sendEmacs', lisp='major-mode')['major_mode']
        LOG.info('Emacs context: %s' % major_mode)
        if self.usereg:
            if self.major_mode.search(major_mode) is None:
                return False
        else:
            if self.major_mode != major_mode:
                return False

        return True


#
# Custom grammars
#

class ConnectRule(CompoundRule):
    spec = "damselfly connect [<server>]"
    extras = [Choice("server", dict([(e, e) for e in servers.keys()]))]

    def _process_recognition(self, node, extras):
        global previous_server, current_server
        server = extras.get('server', current_server)
        connect(*servers[server])
        if current_server == server:
            previous_server = current_server
            current_server = server


class DisconnectRule(CompoundRule):
    spec = "damselfly disconnect"

    def _process_recognition(self, node, extras):
        disconnect()



    def _process_recognition(self, node, extras):


#
# WM control
#

class WMRule(MappingRule):
    mapping = {
        "win hide": HideXWindow(),
        "win hide <text>": HideXWindow("%(text)s"),
        "win cache <text>": CacheXWindow("%(text)s"),
        "win forget <text>": CacheXWindow("%(text)s", forget=True),
        "win focus <text>": FocusXWindow("%(text)s"),
    }
    extras = [
        Dictation("text")
    ]

# these rules consume events which could cause dragon to hang or behave
# strangely in linux


class DNSOverride(MappingRule):
    mapping = {
        "type [<text>]": DoNothing(),
        "MouseGrid [<text>]": DoNothing(),
        "mouse [<text>]": DoNothing(),
        "copy [(that | line)]": DoNothing(),
        "paste [that]": DoNothing(),
    }
    extras = [
        Dictation("text")
    ]

#
# USER DEFINED RULES BELOW THIS POINT                                #
#

# construct one grammar to rule them all
xcon = XAppContext()
grammar = Grammar("Damselfly")
grammar.add_rule(ConnectRule())
grammar.add_rule(DisconnectRule())
grammar.add_rule(DNSOverride())
grammar.add_rule(WMRule(context=xcon))


def unload():
    global xcon, windowCache

    disconnect()

    # does this suffice?
    xcon = None
    windowCache = None

    if grammar.loaded:
        grammar.unload()


grammar.load()
