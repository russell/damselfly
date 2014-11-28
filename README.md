Damselfly
=========

Damselfly is a utility which allows one to use Dragon
NaturallySpeaking to provide input to X11 (under Linux)

Damselfly consists of 2 Python scripts, one which acts as a server and
the other which acts as a client. The server runs on the Linux side
and does the work of interacting with the windowing system. The
client runs on the wine side and and handles command recognition and
dispatching of commands to the server. The client and server
communicate via a pair of named pipes.

Basic installation and setup instructions can be found in the file
named INSTALL.

Damselfly implements a superset of the functionality provided by the
Dragonfly package.  Damselfly does not override any of the classes
provided by Dragonfly, however it implements X aware equivalents where
necessary.  Therefore I am only documenting the differences between
Dragonfly and Damselfly in this file. Please also read the
documentation for Dragonfly found at
http://pythonhosted.org/dragonfly/

The following are the new classes implemented by Damselfly :

Class XKey:
This class functions the same as the Key class from Dragonfly, except
that a meta modifier has been added. Also the Windows key is mapped to
the super key.  So the mapping for the modifier keys is:

    'a' : 'alt'
    'c' : 'ctrl'
    's' : 'shift'
    'w' : 'super'
    'm' : 'meta' 

Class XText:
This class functions the same as the Text class does in Dragonfly 

The constructor has the following signature:
__init__(self, spec, static = False, space = True, title = False, upper = False)

space = False strips spaces from the text
title = True titlecases the text
upper = True makes the string all caps

The Paste class from Dragonfly has no equivalent in Damselfly 

Class XMouse:
This class functions the same as the Mouse class does in Dragonfly,
except that it also implements the mouse wheel buttons. There are
5 different mouse buttons which we can click or press: 'left' ,
'middle' , 'right' , 'wheel up' , and 'wheel down'

Classes WaitXWindow, BringXApp, StartXApp, FocusXWindow are used in
the same way as their non-X Dragonfly equivalents.

The BringXApp and WaitXWindow constructors have a timeout argument
(default 5 seconds).

Class XAppContext:
This is an essential class which does the work of determining whether
a given context applies for an X application.
The constructor has the following signature:
 __init__(self, wmname = None, wmclass = None, wid = None, usereg = False)

Meaning, you can specify an X context via its name (title), or class
(a property set by the application which can accessed with the tool
xprop, typically it defaults to the name of the program), and its
window id (argument 'wid', you can get specific window ids by using
xwininfo for example). The usereg flag specifies whether or not the
wmname / class arguments are to be treated as regular expressions.

If neither wmname nor wmclass are named arguments, it will try to
match the expression to either of these properties. If the connection
between the server and the client is down, XAppContext returns false.

USAGE NOTES:

1. Run the server at the command line, eg do: 
$ ./DamselflyServer.py

2. Run Dragon NaturallySpeaking

3. Say 'damselfly connect' to connect to the server. This will produce
some messages on the consoles.

N.B.

- If the server ever enters a 'stopped' state (it will complain about
  this on the console), which usually happens as a fail-safe if a
  command fails, you need to resume the server by saying 'damselfly
  resume'.

- Editing _Damselfly.py will cause Natlink to reload the grammar once
  the mic has been muted / unmuted, and that will break the
  connection.
