import my_debugger
from my_debugger_defines import *

#Debugger Shell

debugger = my_debugger.debugger()
prompt = lambda : raw_input(">> ")

pid = raw_input("Enter PID of process to attach to:")
# Debugger attaches to process OR loads an exe
debugger.attach(int(pid))
# debugger.load("C:\\WINDOWS\\system32\\calc.exe")

#cmd = prompt()

# Find printf
printf_addr = debugger.func_resolve("msvcrt.dll", "printf")
print "> Addr of prinf: 0x%x" % printf_addr
print 'Set bp at printf? y/n'
if prompt() == 'y':
    debugger.get_bp(printf_addr)

    # All bp types tested with find_prinf.py

debugger.run()

#debugger.detach()
