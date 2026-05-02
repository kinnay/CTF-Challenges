
import os
import secrets

os.system("rm -rf obf")
os.system("cp -r src obf")

def encrypt_string(string, key):
	data = bytes(ord(c) for c in string + "\0")
	return bytes(data[i] ^ ((key >> (8 * (i & 7))) & 0xFF) ^ 0xFF for i in range(len(data)))

index = 0
def process(path):
	global index
	with open(path) as f:
		source = f.read()

	prefix = ""
	
	lines = []
	for line in source.split("\n"):
		if not line.startswith("#"):
			start = line.find('"')
			while start != -1:
				end = line.find('"', start + 1)
				string = eval(line[start:end+1])
				key = secrets.randbits(64)
				cipher = encrypt_string(string, key)
				prefix += f"""
struct struct_{index} {{
	unsigned char data[{len(cipher)}];
	bool decrypted;
	unsigned long key;
}};

static struct_{index} string_{index} = {{
	{{{", ".join(str(x) for x in cipher)}}},
	false,
	{key}u
}};

static const char * __attribute__((noinline, optimize("O0"))) decrypt_{index}(struct_{index} *data) {{
	if (!data->decrypted) {{
		for (int i = 0; i < {len(cipher)}; i++) {{
			data->data[i] = data->data[i] ^ 0xFF ^ ((data->key >> (8 * (i & 7))) & 0xFF);
		}}
		data->decrypted = true;
	}}
	return (const char *)data->data;
}}

#define STRING_{index} decrypt_{index}(&string_{index})
"""
				line = line[:start] + f"STRING_{index}" + line[end+1:]
				start = line.find('"')
				index += 1
		lines.append(line)
	
	code = prefix
	code += "\n".join(lines)
	with open(path, "w") as f:
		f.write(code)

for dirpath, dirnames, filenames in os.walk("obf"):
	for filename in filenames:
		if filename.endswith(".cpp"):
			filepath = os.path.join(dirpath, filename)
			process(filepath)
