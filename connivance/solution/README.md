# Cool Challenge Name

> Bad guys like to obfuscate their code. This challenge implements a part of the DRM behind [Tinfoil](https://tinfoil.io), a homebrew application that enables pirated games on the Nintendo Switch.

## Description
The challenge implements a part of the DRM behind Tinfoil, which enables pirated games on the Nintendo Switch. In Tinfoil, the user can connect to a 'store', which is basically a website that provides game content for free. To prevent people from downloading content outside of Tinfoil, a DRM system is implemented, which conists of the following parts:
* When Tinfoil accesses a store, the `HAUTH` and `UAUTH` headers are sent to the server, which contain a HMAC of the URL using a predefined key.
* The metadata that is provided by the server (such as directory listings) is encrypted in a custom format.

An encrypted file contains the following data:
* The `TINFOIL` magic number, followed by a byte that specifies the compression algorithm that was applied on the plaintext (although the challenge does not use any compression).
* A symmetric key, encrypted with RSA-OAEP.
* The ciphertext, encrypted with AES-ECB using the provided symmetric key.

The decryption is performed using a custom VM, which comes with the following files:
* `connivance.bin`: contains the VM instructions that decrypt the file.
* `blob`: contains a list of encrypted private keys. These are used to decrypt the symmetric key for the file.
* `blob.sig`: contains an RSA signature for the `blob` file.
* `damocles.bin`: contains RSA signatures for the `.text` and `.rodata` segments as an anti-tamper mechanism.
* `map`: contains hashes and information about segments, as yet another anti-tamper mechanism.

The challenge reimplements a part of the VM. The user can specify a program that they want to execute (`hello_world.tfl` and `flag_checker.tfl` are provided with the challenge). The challenge then:
* Executes `connivance.bin` in the VM to decrypt the VM program.
* Executes the decrypted program in the VM.

For the solution, see below.

## Solution
The goal of the challenge is to understand the `flag_checker.tfl` program, so that the flag can be recovered. To analyze this program, it must first be decrypted. This can either be done by reverse engineering the VM and `connivance.bin` to decrypt the program manually, or by placing a breakpoint with a debugger and dumping the decrypted program from memory (placing breakpoints can be tricky due to the anti-tamper mechanisms).

Then, the player must reverse engineer the VM and the decrypted `flag_checker.tfl` program. The best approach is probably to write a basic disassembler for the VM, after the player figures out how the VM instructions are implemented.

The flag verification algorithm consists of a series of SHA-256 checks, most of which are calculated over a subset of the input bits. The hashes are read from `dragonfly.bin`. The flag can be recovered by repeatedly brute forcing bits, until all bits have been recovered. The solution script can be sped up significantly by using the fact that the flag follows the `dach2026{...}` format. This is implemented in `solve.py`.

When reverse engineering a large binary without function names, it helps to automate certain tasks by scripting IDA or Ghidra, such as decrypting strings or giving virtual functions a name.
