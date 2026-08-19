import re
from helpers.crypt.happcrypt import decrypt as decrypt_crypt1to4
from helpers.crypt.happcrypt5 import decrypt as decrypt_crypt5

URL_REGEX = re.compile(r'https?://[^\s<>"\'(){}|\\^`\[\]]+', re.IGNORECASE)

async def decrypt(happ_url: str) -> str:
    path = happ_url[7:] if happ_url.startswith('happ://') else happ_url
    if path.startswith('crypt5/'):
        return await decrypt_crypt5(happ_url)
    elif path.startswith('crypt4/'):
        return await decrypt_crypt1to4(happ_url)
    elif path.startswith('crypt3/'):
        return await decrypt_crypt1to4(happ_url)
    elif path.startswith('crypt2/'):
        return await decrypt_crypt1to4(happ_url)
    elif path.startswith('crypt/'):
        return await decrypt_crypt1to4(happ_url)
    raise ValueError(f"Unknown crypt type: {happ_url}")

async def decrypt_and_extract_url(happ_url: str) -> str:
    result = await decrypt(happ_url)
    for line in result.splitlines():
        urls = URL_REGEX.findall(line)
        if urls:
            return urls[0]
    return None
