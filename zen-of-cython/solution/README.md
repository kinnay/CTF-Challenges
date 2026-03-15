
## Description
The handout contains a Python program that is compiled with Cython. In order to solve the challenge, the player needs to perform the following steps:

1. Understand the protocol that is implemented in the binary and its quirks. The protocol is described in more detail below.
2. Recover the key that is provided to the checksum algorithm. The key is initialized to a random value when the server is started. The easiest way to recover the key is to send a packet with an incorrect checksum to the server, and calculate the checksum key from the response.
3. Recover part of the AES-CTR keystream. Every packet is encrypted with a constant key (generated when the server is started) and a hardcoded nonce. Because the plaintext of certain server responses can be predicted, it is possible to recover the keystream.
4. Register an account on the server and log in. This allows a longer part of the keystream to be recovered.
5. Call AuthenticationService.ListUsers to recover the MD5 hash of the password of the admin account. Because the password of the admin account consists of only 8 hex digits, its password can be brute forced from the hash.
6. Log in as admin and obtain the flag by calling AdminService.GetFlag.

## Approach
The original Python code is lost during compilation, but function names can still be recovered from the binary. The decompilation is quite difficult to read, because a lot of boilerplate code is inserted by Cython. However, it is possible to recover the general structure of the program, including function names. Specific function implementations, such as the checksum algorithm, can be decompiled to Python code by an experienced reverse engineer by hand, or with an LLM (if allowed).

## Protocol
The server listens on TCP port 1337. Everything is encoded in big endian byte order.

Every packet has the following structure:

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Payload size |
| 0x4 | 4 | Checksum |
| 0x8 | | Encrypted payload |

The checksum algorithm is as follows:

```python
def checksum(key, data):
    data += b"\0" * (-len(data) % 4)

    checksum = sum(key)
    for i in range(0, len(data), 4):
        checksum += struct.unpack_from(">I", data, i)[0]
        checksum &= 0xFFFFFFFF
    return checksum
```

The encryption algorithm is AES-CTR. The nonce contains of 12 null bytes. The key for the checksum and encryption algorithm is generated once when the server is started.

For requests, the payload contains the following data after decryption:

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Service id |
| 0x4 | 4 | Method id |
| 0x8 | | Payload |

The payload is encoded with protobuf. The schema depends on the service and method.

For responses, the payload contains the following data after decryption:

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | Result code |
| 0x4 | | Payload |

For more information, and a list of services that are implemented by the server, see the source code.
