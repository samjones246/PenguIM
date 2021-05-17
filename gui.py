import tkinter as tk
import tkinter.scrolledtext as st
import communicate
from threading import Thread, current_thread
import sys
import os
import signal

class MainWindow():
    def __init__(self):
        self.config()
        self.window = tk.Tk()
        self.window.title("PenguIM")
        self.window.columnconfigure(0, weight=1, minsize=150)
        self.window.rowconfigure(0, weight=1)

        self.txt_log = st.ScrolledText(master=self.window)
        self.txt_log.configure(state="disabled")

        self.entry_frame = tk.Frame(master=self.window)
        self.entry_frame.columnconfigure(0, weight=1)
        self.ent_input = tk.Entry(master=self.entry_frame, width=90)
        self.ent_input.bind("<Return>", self.send)
        self.btn_send = tk.Button(master=self.entry_frame, text="Send", command=self.send)

        self.txt_log.grid(row=0, column=0, sticky="nsew")

        self.ent_input.grid(row=0, column=0, sticky="ew")
        self.btn_send.grid(row=0, column=1, sticky="ew")
        self.entry_frame.grid(row=1, column=0, sticky="ew")

        self.txt_log.tag_configure("YOU", foreground="#0000CC", justify="left")
        self.txt_log.tag_configure("THEM", foreground="#CC0000", justify="right")
        self.next_tag = "YOU"
        self.init = True
        self.last = "1.0"
        self.window.mainloop()
        self.disconnect()

    def log_msg(self, msg, tag):
        self.txt_log.configure(state="normal")
        self.txt_log.insert(tk.END, msg)
        self.txt_log.tag_add(tag, self.last, self.txt_log.index("end-1c"))
        self.last = self.txt_log.index("end")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")


    def send(self, event=None):
        msg = ""
        if not self.init:
            msg = "\n"
        else:
            self.init = False
        msg += self.ent_input.get()
        if self.conn:
            communicate.send(self.ent_input.get(), self.conn)
        self.log_msg(msg, "YOU")
        self.ent_input.delete(0, tk.END)
    
    def recv(self, message):
        msg = ""
        if not self.init:
            msg = "\n"
        else:
            self.init = False
        msg += message
        self.log_msg(msg, "THEM")

    def partner_disconnected():
        self.recv("---PARTNER DISCONNECTED---")

    def disconnect(self):
        if "conn" in self.__dict__:
            print("Closing conn...")
            self.conn.close()
            print("conn closed")
        #sys.exit(0)
        #os._exit(0)

    def config(self):
        self.cfwin = tk.Tk()

        frame1 = tk.Frame(master = self.cfwin)
        host_frame = tk.Frame(master=self.cfwin)
        join_frame = tk.Frame(master=self.cfwin)

        def host():
            frame1.destroy()
            self.hosting = True
            host_frame.pack()
            print("1 - " + str(current_thread().name))
            Thread(target=self.host, name="LISTEN").start()

        def join():
            frame1.destroy()
            self.hosting = False
            join_frame.pack()

        frame1.columnconfigure([0,1], weight=1)
        frame1.rowconfigure(0, weight=1)
        btn_host = tk.Button(master = frame1, text="Create Session", command=host)
        btn_join = tk.Button(master = frame1, text="Join Session", command=join)
        btn_host.grid(row=0,column=0)
        btn_join.grid(row=0, column=1)

        lbl_show_ip = tk.Label(master=host_frame, text="Your IP address: XX.XX.XX.XX")
        lbl_waiting = tk.Label(master=host_frame, text="Waiting for partner to connect...")
        lbl_show_ip.pack()
        lbl_waiting.pack()

        lbl_enter_ip = tk.Label(master=join_frame, text="Enter partner IP address:")
        ent_enter_ip = tk.Entry(master=join_frame)
        def connect():
            targetip = ent_enter_ip.get()
            self.connect(targetip)
        btn_connect = tk.Button(master=join_frame, text="Connect", command=connect)
        lbl_enter_ip.pack()
        ent_enter_ip.pack()
        btn_connect.pack()

        frame1.pack()
        self.cfwin.mainloop()

    def connect(self, targetip):
        self.conn = communicate.establish_link(False, targetip, self.recv, self.disconnect)
        self.cfwin.destroy()

    def host(self):
        self.conn = communicate.establish_link(True, None, self.recv, self.disconnect)
        self.cfwin.destroy()

def ctrlc(sig, frame):
    print("CTRLC")
    os._exit(1)

signal.signal(signal.SIGINT, ctrlc)

w = MainWindow()