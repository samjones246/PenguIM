import rsa
import aes
import hmac
from socket import socket
from socketserver import TCPServer 
import typing
from urllib.request import urlopen
import re
from threading import Thread, current_thread
import os

aes_key = None
hmac_key = None
partner_rsa_pub = None
PORT = 1524
RUN = True


def send(message, sock : socket):
    global aes_key, hmac_key
    ciphertext = aes.cfb_encrypt(message.encode("utf-8"), aes_key)
    mac = hmac.hmac(ciphertext, hmac_key)
    payload = mac + ciphertext
    sock.sendall(payload)

def unpack(payload):
    global aes_key, hmac_key
    mac = payload[:32]
    ciphertext = payload[32:]
    if not hmac.verify(ciphertext, hmac_key, mac):
        print("VERIFICATION FAILED")
    message = aes.cfb_decrypt(ciphertext, aes_key)
    return message.decode("utf-8")

def get_external_ip():
    return urlopen('https://ident.me').read().decode('utf8')

def establish_link(hosting, target, recv_callback, dc_callback):
    print("3 - " + str(current_thread().name))
    conn = None
    sock = socket()
    if hosting:
        sock.bind(("localhost", PORT))
        print("Listening for connections...")
        sock.listen()
        conn, addr = sock.accept()
    else:
        sock.connect((target,PORT))
        conn = sock
    init_connection(conn, hosting, recv_callback, dc_callback)
    return conn

def main():
    global PORT
    external_ip = urlopen('https://ident.me').read().decode('utf8')
    conn = None
    addr = None
    hosting = False


    print("1 - Start Session")
    print("2 - Join Session")
    choice = None
    while choice not in ["1","2"]:
        choice = input("> ")
    if choice == "1":
        print("Your IP address: " + external_ip)
        print("Waiting for partner to connect...")
        sock = socket()
        sock.bind(("localhost", PORT))
        sock.listen()
        conn, addr = sock.accept()
        hosting = True
    else:
        print("Enter partner IP address")
        addr = ""
        while re.match("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", addr) is None:
            addr = input("> ")
        sock = socket()
        sock.connect((addr,PORT))
        conn = sock
    
    init_connection(conn, hosting)

def init_connection(conn, hosting, recv_callback, dc_callback):
    global aes_key, hmac_key
    if hosting:
        partner_rsa_pub = rsa.byte_decode_public(conn.recv(132))
        print("Received public key")
        aes_key = aes.gen_key() # 16 byte
        hmac_key = hmac.gen_key() # 32 byte
        payload = rsa.encrypt(aes_key + hmac_key, partner_rsa_pub) # 128 byte
        print("48? " + str(len(payload)))
        print("Sending keys...")
        conn.sendall(payload)
        print("Done")
    else:
        public, private = rsa.gen_key_pair()
        print("Sending public key...")
        conn.sendall(rsa.byte_encode_public(public))
        print("Receiving keys...")
        payload = conn.recv(128)
        print("Done")
        keys = rsa.decrypt(payload, private)
        aes_key = keys[:16]
        hmac_key = keys[16:]
    print("Secure channel established")
    #Thread(target=send_loop(conn), name="SEND").start()
    Thread(target=recv_loop(conn, recv_callback, dc_callback), name="RECV").start()

def send_loop(conn):
    def f():
        global RUN
        while RUN:
            msg = input("> ")
            send(msg, conn)
            if msg == "/dc":
                print("SESSION ENDED")
                RUN = False
    return f

def recv_loop(conn : socket, recv_callback, dc_callback):
    def f():
        global RUN
        n = 0
        while RUN:
            try:
                msg = conn.recv(256)
            except:
                print("Error 1 - Breaking")
                dc_callback()
                print("At break")
                break
            if msg is None:
                if n < 100:
                    print("msg is None")
                elif n % 1000 == 0:
                    print("msg is None")
                n += 1
                continue
            if msg == '':
                print("Error 2 - Breaking")
                dc_callback()
                print("At break")
                break
            unpacked = unpack(msg)
            if unpacked:
                recv_callback(unpacked)
        print("RECV loop ended")
    return f

if __name__ == "__main__":
    main()