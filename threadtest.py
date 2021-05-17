from threading import Thread, current_thread
from time import sleep

def identify():
    for _ in range(10):
        print(current_thread().name)
        sleep(1)

t1 = Thread(target=identify, name="T1")
t2 = Thread(target=identify, name="T2")
t1.start()
t2.start()