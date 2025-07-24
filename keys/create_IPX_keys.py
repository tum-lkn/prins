from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# This script generates a pair of public and private keys for the hIPX and vIPX targets.
def create_keys(target):
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save private key to a file
    with open(f"{target}_private_key.pem", "wb") as f:
        f.write(private_key_pem)

    # Generate public key
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save public key to a file
    with open(f"{target}_public_key.pem", "wb") as f:
        f.write(public_key_pem)

if __name__ == "__main__":
    target = "hIPX"
    create_keys(target)
    print(f"Keys for {target} created successfully.")
    target = "vIPX"
    create_keys(target)
    print(f"Keys for {target} created successfully.")