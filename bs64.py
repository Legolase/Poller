import base64
import argparse

def encodeb64(input: str):
    input_bytes = input.encode("ascii")
    
    base64_bytes = base64.b64encode(input_bytes)
    return base64_bytes.decode("ascii")

def decodeb64(input: str):
    input_bytes = input.encode("ascii")
    
    base64_bytes = base64.b64decode(input_bytes)
    return base64_bytes.decode("ascii")

parser = argparse.ArgumentParser(description='Base64 encoder/decoder')
parser.add_argument("input", type=str, help="Входной файл")
parser.add_argument("output", type=str, help="Выходной файл")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', '--encode', action="store_true", help="Кодировать")
group.add_argument('-d', '--decode', action="store_true", help="Декодировать")

args = parser.parse_args()

with open(args.input, "r") as f:
    with open(args.output, "w") as outf:
        for line in f.readlines():
            line = line.strip()
            outline = ""
            if (args.encode):
                outf.write(f'{encodeb64(line)}\n')
            else:
                outf.write(f'{decodeb64(line)}\n')
    