
from Crypto.Cipher import AES
from dataclasses import dataclass
import os

import google.protobuf.message
import anyio
import enum
import hashlib
import jwt
import secrets
import struct
    
import challenge_pb2


HOST = "0.0.0.0"
PORT = 1337


JWT_KEY = secrets.token_bytes(32)


class ParseError(Exception):
    pass


class ServiceError(Exception):
    def __init__(self, code):
        self.code = code


class InputStream:
    def __init__(self, data):
        self.data = data
        self.pos = 0
    
    def size(self):
        return len(self.data)
    
    def tell(self):
        return self.pos
    
    def seek(self, pos):
        if pos > self.size():
            raise ParseError("Buffer overflow")
        self.pos = pos
    
    def skip(self, num):
        self.seek(self.tell() + num)
    
    def available(self):
        return self.size() - self.tell()
    
    def peek(self, num):
        if self.available() < num:
            raise ParseError("Buffer overflow")
        return self.data[self.pos : self.pos + num]

    def read(self, num):
        data = self.peek(num)
        self.skip(num)
        return data
    
    def readall(self):
        return self.read(self.available())
    
    def u32(self): return struct.unpack(">I", self.read(4))[0]


class OutputStream:
    def __init__(self):
        self.data = b""
    
    def get(self):
        return self.data
    
    def size(self):
        return len(self.data)
    
    def write(self, data):
        self.data += data
    
    def u32(self, value): self.write(struct.pack(">I", value))


class Cryptography:
    def __init__(self):
        self.key = secrets.token_bytes(16)
    
    def checksum(self, data):
        data += b"\0" * (-len(data) % 4)

        checksum = sum(self.key)
        for i in range(0, len(data), 4):
            checksum += struct.unpack_from(">I", data, i)[0]
            checksum &= 0xFFFFFFFF
        return checksum
    
    def encrypt(self, data):
        aes = AES.new(self.key, AES.MODE_CTR, nonce=bytes(12))
        return aes.encrypt(data)
    
    def decrypt(self, data):
        aes = AES.new(self.key, AES.MODE_CTR, nonce=bytes(12))
        return aes.decrypt(data)


class Role(enum.IntEnum):
    Guest = 1
    Admin = 2


class ResultCode(enum.IntEnum):
    Success = 0
    ParseError = 1
    ChecksumError = 2
    UnimplementedMethod = 3
    ExceptionOccurred = 4
    AuthenticationError = 5
    UserAlreadyExists = 6


@dataclass
class User:
    username: str
    password: bytes
    role: Role

    def check_password(self, password):
        return self.password == hashlib.md5(password.encode()).digest()


class Database:
    def __init__(self):
        self.users = {}
    
    def add_user(self, username, password, role):
        password_hash = hashlib.md5(password.encode()).digest()
        user = User(username, password_hash, role)
        self.users[username] = user
    
    def find_user(self, username):
        return self.users.get(username)
    
    def list_users(self):    
        return sorted(self.users.values(), key=lambda user: user.username)


@dataclass
class ServiceRequest:
    service_id: int = 0
    method_id: int = 0
    payload: bytes = b""

    def parse(self, data):
        stream = InputStream(data)
        self.service_id = stream.u32()
        self.method_id = stream.u32()
        self.payload = stream.readall()


@dataclass
class ServiceResponse:
    result: int = 0
    payload: bytes = b""

    def encode(self):
        stream = OutputStream()
        stream.u32(self.result)
        stream.write(self.payload)
        return stream.get()


class ClientHandler:
    def __init__(self, stream, services):
        self.stream = stream
        self.services = services

        self.crypto = Cryptography()

        self.buffer = b""
    
    async def run(self):
        while True:
            try:
                response = await self.process_message()
            except ParseError as e:
                response = ServiceResponse(ResultCode.ParseError, str(e).encode())
            except ServiceError as e:
                response = ServiceResponse(e.code)
            
            await self.send_packet(response.encode())
    
    async def process_message(self):
        data = await self.receive_packet()

        request = ServiceRequest()
        request.parse(data)

        if request.service_id not in self.services:
            raise ServiceError(ResultCode.UnimplementedMethod)
        
        return self.services[request.service_id].handle(request)
    
    async def receive_packet(self):
        while len(self.buffer) < 8:
            self.buffer += await self.stream.receive()
        
        length, checksum = struct.unpack_from(">II", self.buffer)

        while len(self.buffer) < 8 + length:
            self.buffer += await self.stream.receive()

        payload = self.buffer[8:8+length]
        self.buffer = self.buffer[8+length:]
        
        if checksum != self.crypto.checksum(payload):
            raise ServiceError(ResultCode.ChecksumError)
        
        return self.crypto.decrypt(payload)
    
    async def send_packet(self, data):
        data = self.crypto.encrypt(data)
        checksum = self.crypto.checksum(data)

        packet = struct.pack(">II", len(data), checksum) + data
        await self.stream.send(packet)


class Service:
    def __init__(self, database):
        self.database = database

        self.methods = {
        }
    
    def handle(self, request):
        if request.method_id not in self.methods:
            raise ServiceError(ResultCode.UnimplementedMethod)
        
        callback, type, = self.methods[request.method_id]

        argument = type()
        try:
            argument.ParseFromString(request.payload)
        except google.protobuf.message.DecodeError:
            raise ServiceError(ResultCode.ParseError)
        
        response = callback(argument)
        return ServiceResponse(ResultCode.Success, response.SerializeToString())
    
    def authenticate(self, token, role):
        try:
            payload = jwt.decode(token, JWT_KEY, algorithms=["HS256"])
        except Exception:
            return False
        return payload["role"] >= role


class AuthenticationService(Service):
    def __init__(self, database):
        super().__init__(database)

        self.methods = {
            1: (self.login, challenge_pb2.LoginRequest),
            2: (self.register, challenge_pb2.RegisterRequest),
            3: (self.list, challenge_pb2.ListUsersRequest),
        }
    
    def login(self, request):
        user = self.database.find_user(request.username)
        if user is None:
            raise ServiceError(ResultCode.AuthenticationError)
        
        if not user.check_password(request.password):
            raise ServiceError(ResultCode.AuthenticationError)
        
        payload = {
            "username": user.username,
            "role": user.role
        }
        token = jwt.encode(payload, JWT_KEY, algorithm="HS256")
        return challenge_pb2.LoginResponse(token=token)

    def register(self, request):
        if self.database.find_user(request.username):
            raise ServiceError(ResultCode.UserAlreadyExists)
        self.database.add_user(request.username, request.password, Role.Guest)
        return challenge_pb2.RegisterResponse()
    
    def list(self, request):
        if not self.authenticate(request.token, Role.Guest):
            raise ServiceError(ResultCode.AuthenticationError)
        
        response = challenge_pb2.ListUsersResponse()
        for user in self.database.list_users():
            user_object = challenge_pb2.User(
                username=user.username,
                password=user.password,
                role=user.role
            )
            response.users.append(user_object)
        return response


class AdminService(Service):
    def __init__(self, database):
        super().__init__(database)

        self.methods = {
            1: (self.getflag, challenge_pb2.GetFlagRequest)
        }
    
    def getflag(self, request):
        if not self.authenticate(request.token, Role.Admin):
            raise ServiceError(ResultCode.AuthenticationError)
        
        response = challenge_pb2.GetFlagResponse()
        response.flag = os.environ.get("FLAG", "TEC{testflag}")
        return response


class ChallengeServer:
    def __init__(self):
        self.admin_password = secrets.token_hex(4)

        self.database = Database()
        self.database.add_user("admin", self.admin_password, Role.Admin)

        self.authentication_service = AuthenticationService(self.database)
        self.admin_service = AdminService(self.database)

        self.services = {
            100: self.authentication_service,
            101: self.admin_service
        }
    
    async def run(self, host, port):
        listener = await anyio.create_tcp_listener(local_host=host, local_port=port)
        await listener.serve(self.handle)
    
    async def handle(self, stream):
        async with stream:
            handler = ClientHandler(stream, self.services)
            try:
                await handler.run()
            except Exception:
                pass


async def main():
    server = ChallengeServer()
    await server.run(HOST, PORT)


if __name__ == "__main__":
    anyio.run(main, backend="trio")
