import re
import re
from PIL import Image
import io
import numpy as np

data =b"q 612 0 0 10 0 -10 cm\nBI /W 37/H 1/CS/G/BPC 8/L 458/F[\n/AHx\n/DCT\n]ID\nffd8ffe000104a46494600010100000100010000ffdb00430001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001002501011100ffc40017000100030000000000000000000000000006040708ffc400241000000209050100000000000000000000000702050608353776b6b7030436747577ffda0008010100003f00c54d3401dcbbfb9c38db8a7dd265a2159e9d945a086407383aabd52e5034c274e57179ef3bcdfca50f0af80aff00e986c64568c7ffd9\nEI Q \n\nq\nBT\n/ 140 Tf\n10 10 Td\n(Flare-On!)'\nET\nQ\n"


# Step 1: extract inline image data between ID and EI
m = re.search(rb'ID\s*([\da-fA-F\n\r]+)\s*EI', data, re.DOTALL)
if not m:
    print("No inline image found!")
    exit(1)

asciihex_data = m.group(1)
# remove whitespace/newlines
asciihex_data = re.sub(rb'\s+', b'', asciihex_data)

# Step 2: convert ASCIIHex to binary
image_bytes = bytes.fromhex(asciihex_data.decode())

# Step 3: Save as JPEG file for inspection (optional)
with open("inline_image.jpg", "wb") as f:
    f.write(image_bytes)
print("[+] JPEG saved as inline_image.jpg")


img = Image.open("inline_image.jpg")        # path to your extracted image
# Convert to grayscale to get 0-255 single channel
gray = img.convert("L")
arr = np.array(gray)                        # shape: (height, width)

# Flatten row-major and convert each pixel to a char
chars = []
for row in arr:
    for v in row:
        chars.append(chr(int(v)))

decoded = ''.join(chars)
print(repr(decoded))
