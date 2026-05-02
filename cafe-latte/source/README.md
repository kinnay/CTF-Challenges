
This directory contains the file that are required to build the challenge. The challenge can be built by running `build.sh`, which automatically builds and runs the Dockerfile that builds the challenge.

The textures and shader have been compiled to `.gtx` and `.gsh` files with `TexConv2.exe` and `gshCompile.exe` from the official Cafe SDK. Because of their proprietary nature, these tools are not included in this repository. Instead, this repository contains the prebuilt `.gtx` and `.gsh` files, as well as the source files that were used to produce them.

The following commands were used to produce the `.gtx` and `.gsh` files from the source files:
* `TexConv2.exe -i <input.tga> -o <output.gtx>`
* `gshCompile.exe -c <input.cs> -o <output.gsh>`

More information about the source files can be found in the README in the challenge directory.
