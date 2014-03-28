from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
        def __init__(self):
                self.h_process = None
                self.pid = None
                self.debugger_active = False
                self.h_thread = None
                self.context = None
                self.breakpoints = {}
                self.first_breakpoint = True
                self.hardware_breakpoints = {}

                system_info = SYSTEM_INFO()
                kernel32.GetSystemInfo(byref(system_info))
                self.page_size = system_info.dwPageSize #Get page size
                self.guarded_pages = []
                self.memory_breakpoints = {}
                self.single_stepping = False
                
        def load(self,path_to_exe):
                
                # We need these params for CreateProcessA
                # lpApplicationName, lpCommandLine, dwCreationFlags,
                # lpStartupInfo, lpProcessInformation
                
                # dwCreation -> how to create process
                # DEBUG / CREATE_NEW_CONSOLE
                creation_flags = DEBUG_PROCESS
                
                # Create structs for lpStartupInfo, lpProcessInformation
                startupinfo = STARTUPINFO()
                process_info = PROCESS_INFORMATION()
                
                # These allow for separate window for process 
                startupinfo.dwFlags = 0x1
                startupinfo.wShowWindow = 0x0
                # cb holds size of struct
                startupinfo.cb = sizeof(startupinfo)
                
                # Call to create Process 
                if kernel32.CreateProcessA(path_to_exe,
                                                                   None,None,None,None,
                                                                   creation_flags,
                                                                   None,None,
                                                                   byref(startupinfo),
                                                                   byref(process_info)):
                        print "> Process launched successfully "
                        print "> PID: %d" % process_info.dwProcessId
                        
                        # Get handle to process and store
                        self.h_process = self.open_process(process_info.dwProcessId)
                else:
                        print "> Error: %d." % kernel32.GetLastError()

        def open_process(self,pid):
                return kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)
        
        def attach(self,pid):
                # Get handle
                self.h_process = self.open_process(pid)
                # try to attach
                if kernel32.DebugActiveProcess(pid):
                        self.debugger_active = True
                        self.pid = pid
                else:
                        print "> Couldn't attach to process %i" %pid
                        
        def run(self):
                # Here we check for debugging events  
                while self.debugger_active == True:
                        self.get_debug_event()
                        
        def get_debug_event(self):
                
                debug_event= DEBUG_EVENT()
                continue_status = DBG_CONTINUE

                if kernel32.WaitForDebugEvent(byref(debug_event),INFINITE):
                        # Get thread, context
                        self.h_thread = self.open_thread(debug_event.dwThreadId)
                        self.context = self.get_thread_context(h_thread=self.h_thread)

                        # Print event, with thread id
                        print "> Event Code: %d Thread ID: %d" %(debug_event.dwDebugEventCode, debug_event.dwThreadId),

                        if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                                print "Creating Process"

                        elif debug_event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                                print "Creating Thread"

                        elif debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                                print "Leaving Process"

                        elif debug_event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                                print "Leaving Thread"

                        elif debug_event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                                print "Loading a DLL"

                        elif debug_event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
                                print "Unloading a DLL"
                        
                        # if exception was caught
                        elif debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                                print "Exception Caught"
                                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                                
                                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                                        print "> Access Violation Deteected."
                                elif self.exception == EXCEPTION_BREAKPOINT:
                                        continue_status = self.exception_handler_breakpoint()
                                elif self.exception == EXCEPTION_GUARD_PAGE:
                                        print "> Guard Page Access Detected."
                                elif self.exception == EXCEPTION_SINGLE_STEP:
                                        continue_status = self.exception_handler_single_step()
                        
                        kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                                                                debug_event.dwThreadId,
                                                                                continue_status)
                        
        def exception_handler_breakpoint(self):
                # Catch breakpoint
                print "> bp - Exception at: 0x%08x" % self.exception_address

                if not self.breakpoints.has_key(self.exception_address):
                        if self.first_breakpoint:
                                self.first_breakpoint = False
                                print "First Windows driven breakpoint"
                                self.print_registers()
                                self.console()
                                return DBG_CONTINUE
                else:
                        print "Hit user breakpoint"
                        self.print_registers()
                        # Rewrite original byte
                        self.write_process_memory(self.exception_address,self.breakpoints[self.exception_address])

                        # Set EIP back one byte and set context
                        self.context = self.get_thread_context(h_thread=self.h_thread)
                        self.context.Eip -= 1
                        self.set_thread_context(self.context,self.h_thread)
                        self.console()

                        #ans = raw_input("Single step? y/n")
                        #if ans == 'y':
                        #        self.single_step(True)

                        return DBG_CONTINUE
        
        def exception_handler_single_step(self):
                print "> bp_hw - Exception at: 0x%08x" % self.exception_address
                if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
                        slot = 0
                elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
                        slot = 1
                elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
                        slot = 2
                elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
                        slot = 3
                elif self.single_stepping:
                        #print "Single Step", self.single_stepping
                        self.print_registers()
                        self.console()
                        self.single_step(self.single_stepping)
                        return DBG_CONTINUE
                        
                
                if self.bp_del_hw(slot):
                        continue_status = DBG_CONTINUE
                        
                print "> Hardware breakpoint removed"
                return continue_status
        
        def bp_del_hw(self,slot):
                for thread_id in self.enumerate_threads():
                        context = self.get_thread_context(thread_id)
                        context.Dr7 &= ~(1 << (slot*2))
                        
                        if slot == 0:
                                context.Dr0 = 0x00000000
                        elif slot == 1:
                                context.Dr1 = 0x00000000
                        elif slot == 2:
                                context.Dr2 = 0x00000000
                        elif slot == 3:
                                context.Dr3 = 0x00000000
                        
                        # Unset Dr7 condition, length flags
                        context.Dr7 &= ~(3 << ((slot*4)+16))
                        context.Dr7 &= ~(3 << ((slot*4)+18))
                        
                        h_thread = self.open_thread(thread_id)
                        kernel32.SetThreadContext(h_thread,byref(context))
                        
                del self.hardware_breakpoints[slot]
                return True
        
        def bp_set_mem(self,address,size):
                mbi = MEMORY_BASIC_INFORMATION()
                # Getting base address
                if kernel32.VirtualQueryEx(self.h_process,address,
                                                                   byref(mbi),sizeof(mbi)) < sizeof(mbi):
                        return False
                
                current_page = mbi.BaseAddress
                while current_page <= address + size:
                        self.guarded_pages.append(current_page)
                        old_protection = c_ulong(0)
                        if not kernel32.VirtualProtectEx(self.h_process,current_page,size,
                                                         mbi.Protect | PAGE_GUARD, byref(old_protection)):
                                return False
                        current_page += self.page_size
                        
                self.memory_breakpoints[address] = (address,size,mbi)
                return True
        
        # Single Stepping
        def single_step(self,e,h_thread=None):
                if not h_thread:
                        h_thread = self.h_thread

                #context = self.get_thread_context(self.h_thread)
                if e:
                        self.single_stepping = True
                        # Set Trap Flag in EFlags register
                        self.context.EFlags |= EFLAGS_TRAP
                else:
                        self.single_stepping = False
                        self.context.EFlags &= (0xFFFFFFFFFF ^ EFLAGS_TRAP)

                self.set_thread_context(self.context,h_thread=h_thread)

        # Process memory read
        def read_process_memory(self,address,length):
                data = ""
                read_buf = create_string_buffer(length)
                count = c_ulong(0)
                
                if not kernel32.ReadProcessMemory(self.h_process,address,
                                                                                  read_buf,length,byref(count)):
                        return False
                else:
                        data += read_buf.raw
                        return data

        # Process memory write
        def write_process_memory(self,address,data):
                count = c_ulong(0)
                length = len(data)
                c_data = c_char_p(data[count.value])
                
                # if not kernel32.WriteProcessMemory(self.h_process,address,
                #                                    c_data,length,byref(count)):
                #       return False
                # else:
                #   return True
                # Simplify
                return kernel32.WriteProcessMemory(self.h_process,address,
                                                    c_data,length,byref(count))
        
        def bp_set(self,address):
                if not self.breakpoints.has_key(address):
                        try:
                                old_protect = c_ulong(0)
                                kernel32.VirtualProtectEx(self.h_process, address, 1, PAGE_EXECUTE_READWRITE, byref(old_protect))
                                # overwrite byte
                                original_byte = self.read_process_memory(address, 1)
                                self.write_process_memory(address, "\xCC")
                                self.breakpoints[address] = (original_byte)
                        except:
                                print "bp_set failed"
                                return False
                return True
        
        def bp_set_hw(self,address,length,condition):
                # Check length validity
                if length not in (1,2,4):
                        return False
                else:
                        length -= 1
                        
                if condition not in (HW_ACCESS,HW_EXECUTE,HW_WRITE):
                        return False
                
                if not self.hardware_breakpoints.has_key(0):
                        available = 0
                elif not self.hardware_breakpoints.has_key(1):
                        available = 1
                elif not self.hardware_breakpoints.has_key(2):
                        available = 2
                elif not self.hardware_breakpoints.has_key(3):
                        available = 3
                else:
                        return False
                # Set bp in every thread
                for thread_id in self.enumerate_threads():
                        context = self.get_thread_context(thread_id)
                        # Enable in Dr7
                        context.Dr7 |= 1 << (available*2)
                                
                        # Save address into Dr Reg
                        if available == 0:
                                context.Dr0 = address
                        elif available == 1:
                                context.Dr1 = address
                        elif available == 2:
                                context.Dr2 = address
                        elif available == 3:
                                context.Dr3 = address
                        
                        context.Dr7 |= condition << ((available*4)+16)
                        context.Dr7 |= length << ((available*4)+18)
                        
                        h_thread = self.open_thread(thread_id)
                        kernel32.SetThreadContext(h_thread,byref(context))
                
                self.hardware_breakpoints[available] = (address,length,condition)
                
                return True
        
        def func_resolve(self,dll,function):
                # Get address of function from dll
                handle = kernel32.GetModuleHandleA(dll)
                address = kernel32.GetProcAddress(handle,function)
                kernel32.CloseHandle(handle)
                return address
        
        def detach(self):
                # Remove from process
                if kernel32.DebugActiveProcessStop(self.pid):
                        print "> Finished debugging. Exiting!"
                        return True
                else:
                        print "> Couldn't detach process"
                        return False
        
        # Thread Handling    
        def open_thread(self,thread_id):
                # Get thread handle
                h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,None,thread_id)
                
                if h_thread is not None:
                        return h_thread
                else:
                        # Failed
                        print "> Couldn't get a thread handle"
                        return False
                
        def enumerate_threads(self):
                thread_entry = THREADENTRY32()
                thread_list = []    # holds thread ids
                # Get snapshot asking only for threads
                snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
                
                if snapshot is not None:
                        # Set size
                        thread_entry.dwSize = sizeof(thread_entry)
                        # Call to get first thread
                        success = kernel32.Thread32First(snapshot,byref(thread_entry))
                        
                        while success:
                                if thread_entry.th32OwnerProcessID == self.pid:
                                        thread_list.append(thread_entry.th32ThreadID)
                                        # Continue to next thread
                                success = kernel32.Thread32Next(snapshot,byref(thread_entry))
                                
                        kernel32.CloseHandle(snapshot)
                        return thread_list
                else:
                        return False
                
        def get_thread_context(self,thread_id=None,h_thread=None):
                context = CONTEXT()
                context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
                
                # Get thread handle, then the context
                if not h_thread:
                        h_thread = self.open_thread(thread_id)
                if kernel32.GetThreadContext(h_thread,byref(context)):
                        return context
                else:
                        print "thread context failed"
                        return False    #Fail

        def set_thread_context(self,context, h_thread=None):
                if not h_thread:
                        h_thread = self.h_thread

                if not kernel32.SetThreadContext(h_thread,byref(context)):
                        return False;

                #kernel32.CloseHandle(h_thread)
                return True;

        def print_registers(self):
                context = self.get_thread_context(h_thread=self.h_thread)
                print "eip = %08x" % context.Eip,
                print "eax = %08x" % context.Eax,
                print "ebx = %08x" % context.Ebx,
                print "ecx = %08x" % context.Ecx,
                print "edx = %08x" % context.Edx,
                print "edi = %08x" % context.Edi,
                print "esi = %08x" % context.Esi,
                print "ebp = %08x" % context.Ebp,
                print "esp = %08x" % context.Esp

        def get_bp(self,addr=None):
                if addr is None:
                        print 'Enter address:'
                        addr = int(raw_input('>> '),16)
                print 'Choose type of bp: 1) software bp 2) hw bp 3) mem bp'
                cmd = int(raw_input('>> '))
                if cmd == 1:
                        self.bp_set(addr)
                elif cmd == 2:
                        self.bp_set_hw(addr,1,HW_EXECUTE)
                elif cmd == 3:
                        self.bp_set_mem(addr,10)
                else:
                        print 'invalid option, no bp set'

        def console(self):
                print 'Enter c to continue,',
                print 'b to set user breakpoint,',
                print 's to toggle single step,',
                print 'r to print registers,',
                print 'm to read memory,',
                print 'mw to write to memory,',
                #print 'rw to write to registers',
                print 'q to quit'

                while True:
                        cmd = raw_input(">> ")
                        if cmd == 'c':
                                return
                        elif cmd == 'b':
                                self.get_bp()
                        elif cmd == 's':
                                self.single_stepping = not self.single_stepping
                                print "Single Step:", self.single_stepping
                                self.single_step(self.single_stepping)
                        elif cmd == 'r':
                                self.print_registers()
                        elif cmd == 'm':
                                print 'Enter address:'
                                addr = raw_input(">> ")
                                print self.read_process_memory(int(addr,16),8).encode('hex')
                        elif cmd == 'mw':
                                print 'Enter address:'
                                addr = raw_input(">> ")
                                print 'Data:'
                                data = raw_input(">> ")
                                self.write_process_memory(int(addr,16),data)
                        elif cmd == 'rw':
                                #self.write_register()
                                pass
                        elif cmd == 'q':
                                self.detach()
                                return
