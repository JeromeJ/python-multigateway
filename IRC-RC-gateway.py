# Requires Py 3.4+

import collections
import configparser
import contextlib
import email
import io
import json
import os
import select
import socket
import sys
import requests

conf = {}


class dotdict(dict):
    """Allows accessing a dict like an object.
    
    Source: http://stackoverflow.com/a/23689767/
    """
    
    def __getattr__(self, attr):
        # ConfigParser lowerize all params' name but not sections' name
        
        try:
            return self[attr]
        except KeyError:
            return self[attr.lower()]
    
    __setattr__ = dict.__setattr__
    __delattr__ = dict.__delattr__


def parse_headers(raw_headers):
    # Source: http://stackoverflow.com/a/40481308/
    return dict(email.message_from_file(io.StringIO(raw_headers)).items())


def init_rc_hook(host=None, port=None):
    if host is None:
        host = conf.RC.HOST
    
    if port is None:
        port = conf.RC.PORT

    rc_hook = socket.socket()
    rc_hook.setblocking(0)
    
    # Allows quicker reuse of the address after the server is being resetted
    rc_hook.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    rc_hook.bind((host, int(port)))
    
    rc_hook.listen(-1)
    
    return rc_hook


def init_irc_conn(**kwargs):
    # Get the params from kwargs
    # Then from conf.IRC if absent in kwargs
    c = dotdict(
        collections.ChainMap(
            kwargs,
            conf.IRC
        )
    )

    irc = socket.socket()

    irc.connect((c.host, int(c.port)))

    # /!\ setblocking AFTER connect:
    #   connect rely on a DNS server that can't always be non blocking
    #   thus raising an exception.
    irc.setblocking(0)

    if c.password:
        sendcmd(irc, 'PASS {}'.format(c.password))

    sendcmd(irc, 'NICK {}'.format(c.bot_name))
    sendcmd(irc, 'USER {} {} bla :{}'.format(
        c.I,
        c.HOST,
        c.DESCRIPT
    ))
    sendcmd(irc, 'JOIN {}'.format(c.ROOM))

    if c.welcome_msg:
        sendcmd(irc, 'PRIVMSG {} :{}'.format(
            c.ROOM, c.welcome_msg
        ))

    return irc


def sendcmd(s, msg):
    s.sendall((msg+'\r\n').encode('utf-8'))


def sendmsg(s, msg, to=None):
    if to is None:
        to = conf.IRC.ROOM
    
    sendcmd(s, 'PRIVMSG {} :{}'.format(to, msg))

    
def recv_data(s):
    return s.recv(4096).decode('utf-8')


def http_recv_all(s):
    # Reinvented the wheel :)
    # To be able to work with non-blocking sockets and select module.
    
    r = ''
    headers = {}
    
    while 'content-length' not in headers:
        # Note: Blocking but shouldn't be an issue (it's an HTTP request)
        r += recv_data(s)
        
        # Separate headers and content
        headers = r.split('\r\n\r\n', 1)[0]
        
        # Separate request line and headers (eg "GET / HTTP/1.1")
        headers = headers.split('\r\n', 1)[1]
        
        headers = parse_headers(headers)
    
    body = r.split('\r\n\r\n', 1)[1]
    
    # Still not complete? Get moar and retry!
    while len(body.encode('utf-8')) < int(headers['content-length'])-1:
        r += recv_data(s)
        
        body = r.split('\r\n\r\n', 1)[1]
    
    # Properly close the connection or RC will keep spamming until we do.
    s.sendall(b'HTTP/1.0 200 OK\r\n\r\n')
    s.close()
    
    return (headers, body)


def handle_irc(irc, readbuffer, room=None, rc=None):
    if room is None:
        room = conf.IRC.ROOM
    
    if rc is None:
        rc = {}
    
    rc = dotdict(collections.ChainMap(rc, conf.RC))

    new = recv_data(irc)
    
    if new:
        print(new)
    
    # new finishes with "\r\n" IF we received all
    
    # readbuffer may contain uncomplete commands
    readbuffer = readbuffer + new
    
    # Last entry is empty if we received all
    commands = str.split(readbuffer, '\n')
    
    # Contains nothing if we received all
    # Or, ALTERNATIVELY, some uncomplete command
    readbuffer = commands.pop()
    
    # Process all BUT the (potentially) uncomplete command lines (in readbuffer)
    for cmd in commands:
        cmd = str.rstrip(cmd)
        
        print(cmd)
        
        cmd = str.split(cmd)
        
        if cmd[0] == 'PING':
            sendcmd(irc, 'PONG {}'.format(cmd[1]))
            
            print('PONG!')
        elif cmd[1] == 'PRIVMSG' and cmd[2] == room:
            # Ex: :username!idthing PRIVMSG #roomName :My message
            
            # DEV note: Should I use REGEX instead?
            sender = cmd[0].split('!')[0][1:]
            msg = ' '.join(cmd[3:])[1:]
            
            print('{sender}: {msg}'.format(sender=sender, msg=msg))
            
            r = requests.post(
                rc.HOOK_ADDR,
                json={
                    "icon_url": rc.AVATAR_URL.format(sender=sender),
                    "text": rc.msgtemplate.format(
                        sender=sender,
                        msg=msg
                    ),
                }
            )
    
    return readbuffer


def handle_rc_hook(rc_hook, rc_hook_addr=None, msgtemplate=None, bot_name=None, admin_username=None):
    if rc_hook_addr is None:
        rc_hook_addr = conf.RC.HOOK_ADDR
    
    if msgtemplate is None:
        msgtemplate = conf.IRC.msgtemplate
    
    if bot_name is None:
        bot_name = conf.IRC.BOT_NAME
    
    if admin_username is None:
        admin_username = conf.APP.admin_username

    c, _ = rc_hook.accept()
    
    headers, body = http_recv_all(c)
    
    try:
        data = json.loads(body)
        print(data)
    except ValueError:
        print('INVALID JSON ({}): {} {}'.format(len(body), headers, body))
        
        sendmsg(irc, '@{}: Invalid JSON! Go check the logs!'.format(
            admin_username
        ))
        
        requests.post(
            rc_hook_addr,
            json={
                "text": '@{}: Invalid JSON! Go check the logs!'.format(
                    admin_username
                ),
            }
        )
        
        return
    
    # Not our bot nor any others'
    # PREVENT infinite backfeed loop
    if data['user_name'] != bot_name and not data['bot']:
        msg = msgtemplate.format(
            sender=data['user_name'],
            msg=data['text']
        )
        
        print(msg)
        
        sendmsg(irc, msg)


if __name__ == '__main__':
    conf = configparser.ConfigParser()
    conf.read('conf.INI')
    
    import collections
    
    conf = dotdict({
        key: dotdict(val) for key, val in conf.items()
    })
    
    _print = print

    if conf.APP.LOGGING_FILE:
        print('Logging is enabled')
        
        with contextlib.suppress(FileNotFoundError):
            # Back it up if it exists
            os.replace(conf.APP.LOGGING_FILE, conf.APP.LOGGING_FILE + '.BCK')
            
            # Reset on start
            os.remove(conf.APP.LOGGING_FILE)
        
        def print(*args, **kwargs):
            with open(conf.APP.LOGGING_FILE, 'a') as f:
                with contextlib.redirect_stdout(f):
                    _print(*args, **kwargs)
    else:
        def print(*args, **kwargs):
            """Allows for printing in the Windows terminal without crashing."""
            
            try:
                _print(*args, **kwargs)
            except UnicodeEncodeError:
                _print('Can\'t print that!')
    
    with contextlib.suppress(KeyboardInterrupt):
        rc_hook = init_rc_hook()
        irc = init_irc_conn()
        
        readbuffer = ''
        
        while 42:
            rdy2read_sockets, __, __ = select.select([irc, rc_hook], (), ())
            
            for read_s in rdy2read_sockets:
                if read_s is irc:
                    # Incoming IRC commands
                    readbuffer = handle_irc(irc, readbuffer)
                else:
                    # Incoming http POST request
                    handle_rc_hook(rc_hook)

    with contextlib.suppress(NameError):
        irc.close()
    
    with contextlib.suppress(NameError):
        rc_hook.close()