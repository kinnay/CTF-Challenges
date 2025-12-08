
from PIL import Image
import os
import streams
import yaml

actor_types = [
    "invalid",
    "hud",
    "player",
    "background",
    "solid",
    "text",
    "item",
    "effect",
    "flag",
    "trophy",
    "block",
    "dialog",
    "spikes",
    "solidontop"
]

def walk(folder):
    files = []
    for dirpath, dirnames, filenames in os.walk(folder):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            files.append(filepath[len(folder)+1:])
    return files

textures = walk("assets/textures")
spritesheets = walk("assets/spritesheets")
fonts = walk("assets/fonts")
sprites = walk("assets/sprites")
sounds = walk("assets/sounds")
levels = walk("assets/levels")

stream = streams.StreamOut("<")
stream.u8(len(textures))
for filename in textures:
    name = filename.split(".")[0]
    im = Image.open(os.path.join("assets/textures", filename))
    stream.u8(len(name))
    stream.ascii(name)
    stream.u16(im.width)
    stream.u16(im.height)
    stream.write(im.convert("RGBA").tobytes())

stream.u8(len(spritesheets))
for filename in spritesheets:
    name = filename.split(".")[0]
    with open(os.path.join("assets/spritesheets", filename)) as f:
        spritesheet = yaml.safe_load(f)
    
    texture = spritesheet["texture"]
    
    stream.u8(len(name))
    stream.ascii(name)
    stream.u8(len(texture))
    stream.ascii(texture)
    stream.u8(int(spritesheet["width"]))
    stream.u8(int(spritesheet["height"]))

stream.u8(len(fonts))
for filename in fonts:
    name = filename.split(".")[0]
    with open(os.path.join("assets/fonts", filename)) as f:
        font = yaml.safe_load(f)
    
    spritesheet = font["spritesheet"]
    chars = font["chars"]
    
    stream.u8(len(name))
    stream.ascii(name)
    stream.u8(len(spritesheet))
    stream.ascii(spritesheet)
    stream.u8(len(chars))
    stream.ascii(chars)

stream.u8(len(sprites))
for filename in sprites:
    name = filename.split(".")[0]
    with open(os.path.join("assets/sprites", filename)) as f:
        sprite = yaml.safe_load(f)
    
    spritesheet = sprite["spritesheet"]
    timings = sprite.get("timings", [0])
    indices = sprite.get("indices", list(range(len(timings))))
    
    stream.u8(len(name))
    stream.ascii(name)
    stream.u8(len(spritesheet))
    stream.ascii(spritesheet)
    stream.u8(len(timings))
    stream.repeat(timings, stream.u8)
    stream.repeat(indices, stream.u8)
    stream.u8(sprite.get("loop", 0))

stream.u8(len(sounds))
for filename in sounds:
    name = filename.split(".")[0]
    with open(os.path.join("assets/sounds", filename), "rb") as f:
        data = f.read()
    
    stream.u8(len(name))
    stream.ascii(name)
    stream.u32(len(data))
    stream.write(data)

stream.u8(len(levels))
for filename in levels:
    name = filename.split(".")[0]
    with open(os.path.join("assets/levels", filename)) as f:
        level = yaml.safe_load(f)
    
    actors = level.get("actors", [])
    camera = level.get("camera", {})
    
    stream.u8(len(name))
    stream.ascii(name)

    stream.s16(camera.get("min_x", 0) * 16)
    stream.s16(camera.get("max_x", 0) * 16)

    stream.u8(len(actors))
    for actor in actors:
        type = actor["type"]
        text = actor.get("text", "") or actor.get("message", "")
        texture = actor.get("texture") or actor.get("font", "") or actor.get("sprite", "")
        param = actor.get("id") or actor.get("param") or 0

        stream.u8(actor_types.index(type))
        stream.s16(int(actor.get("x", 0) * 16))
        stream.s16(int(actor.get("y", 0) * 16))
        stream.u8(int(actor.get("nx", 1)))
        stream.u8(int(actor.get("ny", 1)))
        stream.u16(int(actor.get("dx", 1) * 16))
        stream.u16(int(actor.get("dy", 1) * 16))
        stream.u8(int(actor.get("w", 1)))
        stream.u8(int(actor.get("h", 1)))
        stream.u8(len(texture))
        stream.ascii(texture)
        stream.u8(len(text))
        stream.ascii(text)
        stream.u8(param)

data = stream.get()
with open("assets.arc", "wb") as f:
    f.write(data)
