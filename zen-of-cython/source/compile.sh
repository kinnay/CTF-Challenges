
python3 -m grpc_tools.protoc -I. challenge.proto --python_out=.

rm -rf build
mkdir build

cat challenge_pb2.py main.py > build/challenge.py
python3 patch.py

cython --embed -3 -o build/challenge.c build/challenge.py

gcc -s build/challenge.c -o main $(python3-config --embed --cflags --ldflags)
