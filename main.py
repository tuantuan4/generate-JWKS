import os
import subprocess
from jwcrypto import jwk, jwt

key_name = "190ad"  # change as required
key_type = "RSA"
alg = "RS256"
size = 2048
use = "sig"


def create_keys(key_name):
    """Create all of the keys and save in keys directory"""
    key = jwk.JWK.generate(kty=key_type, size=size, kid=key_name, use=use, alg=alg)

    with open(f"keys/{key_name}_private.json", "w") as writer:
        writer.write(key.export_private())

    with open(f"keys/{key_name}_public.json", "w") as writer:
        writer.write(key.export_public())

    with open(f"keys/{key_name}.pem", "w") as writer:
        writer.write(key.export_to_pem("private_key", password=None).decode("utf-8"))

    # Output private key to RSA format for Terraform using openssl
    args = [
        "openssl",
        "rsa",
        "-in",
        f"keys/{key_name}.pem",
        "-out",
        f"keys/{key_name}_rsa.pem",
    ]
    subprocess.run(args)


if not os.path.exists("keys"):
    os.makedirs("keys")
    create_keys(key_name=key_name)
    print("Keys created. Please move to secure storage and remove the keys directory.")
else:
    print(
        "Please remove existing keys directory- make sure you have the existing keys stored securely because this "
        "will generate new ones!"
    )

private_key_file = f"keys/{key_name}_private.json"
with open(private_key_file, "r") as key_file:
    jwk_private = jwk.JWK.from_json(key_file.read())

# Payload cho JWT
payload = {
    "scp": ["scope-a", "scope-b"]
}
jwt_header = {
    'alg': 'RS256',
    'kid': '190ad',
    'typ': 'JWT'
}
key = jwk.JWK.generate(kty=key_type, size=size, kid=key_name, use=use, alg=alg)
key.export()
# Tạo JWT
jwt_token = jwt.JWT(
    header=jwt_header,
    claims=payload,
)
# jwt_token = jwt.encode(payload, jwk_private.export_to_pem(), algorithm=alg)
jwt_token.make_signed_token(key)
jwt_token.serialize()
print("JWT Token:")
print(jwt_token)

