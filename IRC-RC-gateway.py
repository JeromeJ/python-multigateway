# Requires Py 3.4+

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

conf = configparser.ConfigParser()
conf.read('conf.INI')

_print = print

if conf['APP']['LOGGING_FILE']:
    print('Logging is enabled')
    
    with contextlib.suppress(FileNotFoundError):
        # Back it up if it exists
        os.replace(conf['APP']['LOGGING_FILE'], conf['APP']['LOGGING_FILE'] + '.BCK')
        
        # Reset on start
        os.remove(conf['APP']['LOGGING_FILE'])
    
    def print(*args, **kwargs):
        with open(conf['APP']['LOGGING_FILE'], 'a') as f:
            with contextlib.redirect_stdout(f):
                _print(*args, **kwargs)
else:
    def print(*args, **kwargs):
        """ Allows for printing in the Windows terminal without crashing. Very basic """
        
        try:
            _print(*args, **kwargs)
        except UnicodeEncodeError:
            _print('Can\'t print that!')


def parse_headers(raw_headers):
    # Source: http://stackoverflow.com/a/40481308/
    return dict(email.message_from_file(io.StringIO(raw_headers)).items())


def sendcmd(s, msg):
    s.sendall((msg+'\r\n').encode('utf-8'))


def sendmsg(s, msg, to=conf['IRC']['ROOM']):
    sendcmd(s, 'PRIVMSG {} :{}'.format(to, msg))

    
def recv_data(s):
    return s.recv(4096).decode('utf-8')


def http_recv_all(s):
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
    
    while len(body.encode('utf-8')) < int(headers['content-length'])-1:
        r += recv_data(s)
        
        body = r.split('\r\n\r\n', 1)[1]
    
    s.sendall(b'HTTP/1.0 200 OK\r\n\r\n')
    s.close()
    
    return {'headers': headers, 'body': body}


def handle_irc(irc, readbuffer):
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
        elif cmd[1] == 'PRIVMSG' and cmd[2] == conf['IRC']['ROOM']:
            # Ex: :username!idthing PRIVMSG #roomName :My message
            
            # DEV note: Should I use REGEX instead?
            sender = cmd[0].split('!')[0][1:]
            msg = ' '.join(cmd[3:])[1:]
            
            print('{sender}: {msg}'.format(sender=sender, msg=msg))
            
            r = requests.post(
                conf['RC']['HOOK_ADDR'],
                json={
                    "icon_url": conf['RC']['AVATAR_URL'].format(sender=sender),
                    "text": conf['TEMPLATES']['RC_msg'].format(
                        sender=sender,
                        msg=msg
                    ),
                }
            )
    
    return readbuffer


def handle_rc_hook(rc_hook):
    c, _ = rc_hook.accept()
    
    headers, body = http_recv_all(c)
    
    try:
        data = json.loads(body)
    except ValueError:
        print('INVALID JSON ({}): {} {}'.format(len(body), headers, body))
        
        sendmsg(irc, '@{}: Invalid JSON! Go check the logs!'.format(
            conf['APP']['admin_username']
        ))
        
        requests.post(
            conf['RC']['HOOK_ADDR'],
            json={
                "text": '@{}: Invalid JSON! Go check the logs!'.format(
                    conf['APP']['admin_username']
                ),
            }
        )
    
    print(data)
    
    # Not our bot nor any others'
    # PREVENT infinite backfeed loop
    if data['user_name'] != conf['IRC']['BOT_NAME'] and not data['bot']:
        msg = conf['TEMPLATES']['IRC_msg'].format(
            sender=data['user_name'],
            msg=data['text']
        )
        
        print(msg)
        
        sendmsg(irc, msg)

try:
    rc_hook = socket.socket()
    rc_hook.setblocking(0)
    
    # Allows quicker reuse of the address after the server is being resetted
    rc_hook.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    rc_hook.bind((
        conf['RC']['HOST'],
        int(conf['RC']['PORT'])
    ))
    
    rc_hook.listen(-1)
    
    irc = socket.socket()
    
    irc.connect((
        conf['IRC']['HOST'],
        int(conf['IRC']['PORT'])
    ))
    
    # /!\ setblocking AFTER connect:
    #   connect rely on a DNS server that can't always be non blocking
    #   thus raising an exception.
    irc.setblocking(0)
    
    if conf['IRC']['PASSWORD']:
        sendcmd(irc, 'PASS {}'.format(conf['IRC']['PASSWORD']))
    
    sendcmd(irc, 'NICK {}'.format(conf['IRC']['BOT_NAME']))
    sendcmd(irc, 'USER {} {} bla :{}'.format(
        conf['IRC']['I'],
        conf['IRC']['HOST'],
        conf['IRC']['DESCRIPT']
    ))
    sendcmd(irc, 'JOIN {}'.format(conf['IRC']['ROOM']))
    
    if conf['IRC']['welcome_msg']:
        sendcmd(irc, 'PRIVMSG {} :{}'.format(
            conf['IRC']['ROOM'], conf['IRC']['welcome_msg']
        ))
    
    readbuffer = ''
    
    while 42:
        rdy2read_sockets, __, __ = select.select([irc, rc_hook], (), ())
        
        for read_s in rdy2read_sockets:
            if read_s is irc:
                readbuffer = handle_irc(irc, readbuffer)
            else:
                handle_rc_hook(rc_hook)

except KeyboardInterrupt:
    # sendmsg(irc, 'Bye bye~')
    pass
finally:
    with contextlib.suppress(NameError):
        s.close()
    
    with contextlib.suppress(NameError):
        rc_hook.close()
