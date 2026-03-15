
from pathlib import Path

path = Path("build/challenge.py")
text = path.read_text()

text = text.replace("import challenge_pb2\n", "")
text = text.replace("challenge_pb2.", "challenge_pb2_")

marker = "_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'challenge_pb2', _globals)\n"
aliases = """\
challenge_pb2_User = _globals['User']
challenge_pb2_LoginRequest = _globals['LoginRequest']
challenge_pb2_LoginResponse = _globals['LoginResponse']
challenge_pb2_RegisterRequest = _globals['RegisterRequest']
challenge_pb2_RegisterResponse = _globals['RegisterResponse']
challenge_pb2_ListUsersRequest = _globals['ListUsersRequest']
challenge_pb2_ListUsersResponse = _globals['ListUsersResponse']
challenge_pb2_GetFlagRequest = _globals['GetFlagRequest']
challenge_pb2_GetFlagResponse = _globals['GetFlagResponse']
"""

if marker not in text:
    raise SystemExit('protobuf builder marker not found')

text = text.replace(marker, marker + aliases, 1)

# Replace docstring of challenge.py
text = text.replace("Generated protocol buffer code.", "Good luck!")

path.write_text(text)
