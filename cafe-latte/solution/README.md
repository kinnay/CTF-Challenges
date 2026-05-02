
This document summarizes the challenge, and the steps that need to be taken to arrive at the solution. The script `solve.py` also produces the flag from the handout.

### 1. Unpack the WUHB archive
The handout has the `.wuhb` format, which is the "Wii U Homebrew Bundle" format that was introduced by the [Aroma homebrew environment](https://aroma.foryour.cafe). The format of such a bundle can be derived from the source code of [libromfs_wiiu](https://github.com/wiiu-env/libromfs_wiiu/blob/main/source/romfs_dev.cpp), [Cemu](https://github.com/cemu-project/Cemu/blob/main/src/Cafe/Filesystem/WUHB/WUHBReader.cpp) or [wuhbtool](https://github.com/devkitPro/wut-tools/blob/master/src/wuhbtool/services/RomFSService.cpp).

### 2. Disassemble the main executable
Once unpacked, the player finds a `code`, `content` and `meta` folder. Only the `code` folder is relevant for the solution. It contains the main executable named `root.rpx`. RPX/RPL is a custom file format, based on ELF, that was designed by Nintendo for the Wii U. It can be loaded into Ghidra or IDA with one of the following plugins:
* https://github.com/Maschell/GhidraRPXLoader
* https://github.com/decaf-emu/ida_rpl_loader
* https://github.com/aerosoul94/ida_gel

Alternatively, it is possible to to use one of the rpl2elf tools, although the ELF file that is produced by them seems somewhat broken:
* https://github.com/Relys/rpl2elf
* https://github.com/rw-r-r-0644/rpl2elf

If the participant wants to parse the executable manually, they might inspect the various tools that are available in the [wut-tools](https://github.com/devkitPro/wut-tools) repository.

### 3. Analyze the main executable
Because the binary has not been stripped, it should be not be difficult to find the flag verification algorithm. The player will find the `App::check_input`, which internally calls `App::run_shader`. There, the player will see that a compute shader is executed by the game.

An experienced reverse engineer may also notice the Rijndael S-box in the binary, which is normally used for the AES algorithm. This can also be found with a plugin, such as [findcrypt](https://github.com/polymorf/findcrypt-yara). This s-box is used by the AES algorithm that is implemented in the shader.

### 4. Analyze the compute shader
This is probably the most difficult part of the challenge. While current Wii U emulators can execute vertex, fragment and geometry shaders, support for compute shaders is lacking. In addition, most of the control flow graph was lost during compilation, because shader compilers tend to aggressively inline functions and unroll loops. This part will likely make even the most experienced reverse engineers stumble. Hopefully they still enjoy the challenge :).

There are several ways in which the player can approach the challenge:
1. Disassemble the shader and analyze it statically. In order to build a disassembler, the player can consult one of the Wii U emulators ([decaf-emu](https://github.com/decaf-emu/decaf-emu) or [Cemu](https://github.com/cemu-project/Cemu)), or the R600 ISA that is published on the website of AMD.
2. Attempt to build an emulator for the shader, either by extending an existing Wii U emulator, or by building a compute shader emulator from scratch.

Probably, the best approach is to do a bit of both.

Note that precompiled shaders are a unique aspect of game consoles. Precompiled shaders are only possible because the developer knows exactly which GPU they are targeting. Wii U developers are even *required* to compile their shaders in advance. The graphics system of the Wii U does not provide any support for shader compilation at runtime. In contrast, PC games are usually required to ship the source code of the shader instead, because they cannot know which GPU is running on the player's computer in advance.

### 5. Recover the flag
If the player manages to understand the input verification algorithm, they can recover the flag. To recover the correct input, they need to solve a matrix over `GF(2)`. The input can then be used to decrypt the flag with AES-ECB. More information on the algorithm can be found in the source code of this challenge.
