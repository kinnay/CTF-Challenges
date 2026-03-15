
This directory contains the source code of the challenge and a build script. During compilation, we concatenate challenge_pb2.py and main.py into a single Python file. This makes it more difficult for players to import challenge_pb2.py into a Python shell.

Some patches are applied to challenge_pb2.py to make it compatible with the Cython compiler (see patch.py).

The handout of the challenge was built on Ubuntu 24.04 with Python 3.12.3, grpcio-tools 1.72.1, Cython 3.1.6 and GCC version 13.3.0.
