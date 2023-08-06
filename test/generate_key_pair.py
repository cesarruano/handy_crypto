from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sys

def generate_key_pair():
    # Generate a new RSA private key with a key length of 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Serialize the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def generate_cpp_header(file_name):
    input_file = file_name+'.pem'
    output_file = file_name+'.h'

    try:
        with open(input_file, 'r') as pem_file:
            pem_content = pem_file.read()

        with open(output_file, 'w') as header_file:
            header_file.write('#pragma once\n\n')
            header_file.write('const std::string '+file_name+' = R"(\n')
            header_file.write(pem_content)
            header_file.write(')";\n')

        print(output_file + " generated successfully.")
    except Exception as e:
        print("An error occurred: " + str(e))
    
if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "keygen":
        private_key_pem, public_key_pem = generate_key_pair()

        # Save the keys to files (optional)
        with open('private_key.pem', 'wb') as f:
            f.write(private_key_pem)

        with open('public_key.pem', 'wb') as f:
            f.write(public_key_pem)
    generate_cpp_header("private_key")
    generate_cpp_header("public_key")
