import json, base64, os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

_BASEDIR = os.path.dirname(os.path.abspath(__file__))

def decrypt_crypt1to4(ordinal: int, payload: str) -> str:
    with open(os.path.join(_BASEDIR, "keys", "happcrypt.json"), "r", encoding="utf-8") as f:
        keys = json.load(f)["keys"]
    pkcs1_b64 = keys[ordinal]["key"]
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{pkcs1_b64}\n-----END RSA PRIVATE KEY-----"
    private_key = serialization.load_pem_private_key(pem.encode(), password=None)
    key_size = private_key.key_size // 8
    
    payload = payload.replace('-', '+').replace('_', '/') + '=' * (-len(payload) % 4)
    cipher_bytes = base64.b64decode(payload)
    
    chunks = [private_key.decrypt(cipher_bytes[i:i+key_size], padding.PKCS1v15()) for i in range(0, len(cipher_bytes), key_size)]
    return b"".join(chunks).decode('utf-8')

async def decrypt(link: str) -> str:
    path = link[7:] if link.startswith('happ://') else link
    if path.startswith('crypt4/'): return decrypt_crypt1to4(3, path[7:])
    if path.startswith('crypt3/'): return decrypt_crypt1to4(2, path[7:])
    if path.startswith('crypt2/'): return decrypt_crypt1to4(1, path[7:])
    if path.startswith('crypt/'): return decrypt_crypt1to4(0, path[6:])
    raise ValueError("Not crypt1-4")
