import json
import re
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

_BASEDIR = os.path.dirname(os.path.abspath(__file__))

def swap_pairs(s: str) -> str:
    arr = list(s)
    for i in range(0, len(arr) - 1, 2):
        arr[i], arr[i+1] = arr[i+1], arr[i]
    return "".join(arr)

def b64_decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/') + '=' * (-len(s) % 4)
    return base64.b64decode(s)

def block_pair_swap(s: str) -> str:
    full_len = len(s) - (len(s) % 4)
    out = []
    for offset in range(0, full_len, 4):
        out.append(s[offset + 2 : offset + 4])
        out.append(s[offset : offset + 2])
    out.append(s[full_len:])
    return "".join(out)

async def decrypt(link: str) -> str:
    payload = link
    if payload.startswith("happ://crypt5/"):
        payload = payload[14:]
    elif payload.startswith("crypt5/"):
        payload = payload[7:]
    elif payload.startswith("happ://"):
        payload = payload[7:]

    shuffled = block_pair_swap(payload)
    if len(shuffled) < 8:
        raise ValueError("crypt5 payload too short")

    marker = shuffled[:4] + shuffled[-4:]
    
    body = shuffled[4:-4]
    if len(body) < 13:
        raise ValueError("crypt5 body too short")

    nonce_str = body[:12]
    rest = body[12:]
    
    digit_match = re.match(r'^(\d+)', rest)
    if not digit_match:
        raise ValueError("crypt5 segment length missing")
        
    segment_len = int(digit_match.group(1))
    packed = rest[len(digit_match.group(1)):]
    
    if len(packed) < 1 + segment_len:
        raise ValueError("crypt5 segment truncated")
        
    url_b64 = packed[1 : 1 + segment_len]
    enc_str = packed[1 + segment_len:]

    with open(os.path.join(_BASEDIR, "keys", "happcrypt5.json"), "r", encoding="utf-8") as f:
        keys = json.load(f)
        
    rsa_key_b64 = keys.get(marker)
    if not rsa_key_b64:
        raise ValueError(f"No RSA key found for marker: {marker}")

    pem = f"-----BEGIN PRIVATE KEY-----\n{rsa_key_b64}\n-----END PRIVATE KEY-----"
    pk = serialization.load_pem_private_key(pem.encode(), password=None)
    
    cipher_bytes = b64_decode(enc_str)
    rsa_plain = pk.decrypt(cipher_bytes, padding.PKCS1v15()).decode('latin-1')

    chacha_key = b64_decode(swap_pairs(rsa_plain))
    chacha = ChaCha20Poly1305(chacha_key)
    
    nonce_bytes = nonce_str.encode('utf-8')
    url_cipher_bytes = b64_decode(url_b64)
    
    intermediate_bytes = chacha.decrypt(nonce_bytes, url_cipher_bytes, None)
    intermediate_str = intermediate_bytes.decode('utf-8')

    final_url = b64_decode(swap_pairs(intermediate_str)).decode('utf-8')
    return final_url
