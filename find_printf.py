from ctypes import *
import time

msvcrt = cdll.msvcrt
count = 0

while True:
    msvcrt.printf("Loop iteration %d!\n"%count)
    time.sleep(1)
    count+=1