from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

# Generate 32-byte encryption key
key = os.urandom(32)

# Generate 16-byte initialization vector
iv = os.urandom(16)

# Create C++ header file
with open("aes_key.h", "w") as file:
    file.write("#pragma once\n\n")
    file.write("const unsigned char aes_encryption_key[] = { ")
    file.write(", ".join(f"0x{b:02x}" for b in key))
    file.write(" };\n\n")
    file.write("const unsigned char aes_encryption_iv[] = { ")
    file.write(", ".join(f"0x{b:02x}" for b in iv))
    file.write(" };\n")
