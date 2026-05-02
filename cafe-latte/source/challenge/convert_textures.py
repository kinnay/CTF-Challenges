
from PIL import Image
import os
import subprocess


def walk(folder: str) -> list[str]:
    files = []
    for dirpath, _, filenames in os.walk(folder):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            files.append(filepath[len(folder)+1:])
    return files


for texture in walk("assets"):
    name = os.path.splitext(texture)[0]
    inpath = os.path.join("assets", texture)
    outpath = os.path.join("fs/content/textures", name + ".gtx")

    print(f"Converting {texture}...")
    
    os.makedirs(os.path.dirname(outpath), exist_ok=True)

    im = Image.open(inpath)
    alpha = im.convert("RGBA")
    alpha.save("temp.tga")

    subprocess.run(["wine", "tools/TexConv2.exe", "-i", "temp.tga", "-o", outpath])
    subprocess.run(["rm", "temp.tga"])
