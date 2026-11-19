#!/usr/bin/env python3
"""Regenerates the derived bytes of the empty.vault/1 test vectors independently of the TypeScript core.

Uses only Python stdlib (HKDF/HMAC/SHA-2/Base32, hand-written CBOR, Ed25519 point arithmetic for the
negative cases), libsodium through ctypes (XChaCha20-Poly1305-IETF, Ed25519 verification) and Node.js/OpenSSL
(Ed25519 signing). Fixture inputs (keys, nonces, IDs, salts, passwords, Argon2id output) are read from the
existing vectors and kept; only label-dependent outputs are recomputed.

Usage: python3 -I scripts/vectors/generate_v1.py [--check]
"""
import ctypes
import ctypes.util
import base64
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = ROOT / 'test-vectors'
CHECK = '--check' in sys.argv[1:]

# ---------- libsodium ----------
_path = ctypes.util.find_library('sodium') or '/opt/homebrew/lib/libsodium.dylib'
sodium = ctypes.CDLL(_path)
if sodium.sodium_init() < 0:
    raise SystemExit('sodium_init failed')


def xchacha_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    assert len(key) == 32 and len(nonce) == 24
    out = ctypes.create_string_buffer(len(plaintext) + 16)
    out_len = ctypes.c_ulonglong()
    rc = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        out, ctypes.byref(out_len), plaintext, ctypes.c_ulonglong(len(plaintext)),
        aad, ctypes.c_ulonglong(len(aad)), None, nonce, key)
    assert rc == 0
    return out.raw[:out_len.value]


def sodium_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    return sodium.crypto_sign_verify_detached(signature, message, ctypes.c_ulonglong(len(message)), public_key) == 0


# ---------- stdlib primitives ----------
def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b'', b'', 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    for size, code in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 1 << (8 * size):
            return bytes([major << 5 | code]) + value.to_bytes(size, 'big')
    raise ValueError(value)


def cbor_bstr(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def cbor_map(entries) -> bytes:
    """entries: list of (small unsigned int key, already-encoded value) in canonical order."""
    return cbor_head(5, len(entries)) + b''.join(cbor_head(0, k) + v for k, v in entries)


MAGIC = b'SPCE'


def frame(kind: int, body: bytes) -> bytes:
    return MAGIC + bytes([0, 1, kind]) + len(body).to_bytes(4, 'big') + body


def b32(data: bytes, chars: int) -> str:
    return base64.b32encode(data).decode().rstrip('=')[:chars]


# ---------- Ed25519 (RFC 8032 arithmetic, used only to build negative cases) ----------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = 2 * t1 * t2 * D % P
    Dd = 2 * z1 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def point_mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = point_add(q, p)
        p = point_add(p, p)
        s >>= 1
    return q


def point_compress(p):
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def point_decompress(data: bytes):
    y = int.from_bytes(data, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    assert (x * x - x2) % P == 0
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, x * y % P)


BASE = point_decompress((4 * pow(5, P - 2, P) % P).to_bytes(32, 'little'))


def challenge(r: bytes, a: bytes, message: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r + a + message).digest(), 'little') % L


def fixture_scalar(label: str) -> int:
    return int.from_bytes(hashlib.sha512(label.encode()).digest(), 'little') % L or 1


def small_order_r_case(message: bytes):
    """R = identity and S = k*a: the cofactorless equation holds, but libsodium rejects small-order R."""
    a = fixture_scalar('empty.vault/1 negative small-order-R key')
    public = point_compress(point_mul(a, BASE))
    r = point_compress((0, 1, 1, 0))
    s = challenge(r, public, message) * a % L
    return public, r + s.to_bytes(32, 'little')


def mixed_order_key_case(message: bytes):
    """A = aB + T with T of order 8; R = rB, S = r + k*a: valid only under cofactored verification."""
    torsion = point_decompress(bytes.fromhex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'))
    assert point_compress(point_mul(8, torsion)) == point_compress((0, 1, 1, 0))
    a = fixture_scalar('empty.vault/1 negative mixed-order key')
    r_scalar = fixture_scalar('empty.vault/1 negative mixed-order nonce')
    for _ in range(64):
        public = point_compress(point_add(point_mul(a, BASE), torsion))
        r = point_compress(point_mul(r_scalar, BASE))
        k = challenge(r, public, message)
        if k % 8:  # k*T != identity, so the cofactorless equation must fail
            s = (r_scalar + k * a) % L
            return public, r + s.to_bytes(32, 'little')
        r_scalar += 1
    raise RuntimeError('no suitable nonce')


def openssl_sign(seed: bytes, message: bytes) -> bytes:
    script = (
        "const c=require('node:crypto');const [s,m]=process.argv.slice(1);"
        "const der=Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(s,'hex')]);"
        "const k=c.createPrivateKey({key:der,format:'der',type:'pkcs8'});"
        "process.stdout.write(c.sign(null,Buffer.from(m,'hex'),k).toString('hex'))"
    )
    return bytes.fromhex(subprocess.check_output(['node', '-e', script, seed.hex(), message.hex()], cwd='/').decode())


# ---------- vectors ----------
def load(name):
    return json.loads((VECTORS / name).read_text())


changed = []


def save(name, data):
    text = json.dumps(data, indent=2, ensure_ascii=False) + '\n'
    path = VECTORS / name
    if path.read_text() != text:
        changed.append(name)
        if not CHECK:
            path.write_text(text)


h = lambda v: bytes.fromhex(v)

# HKDF vault-wrap-key
hv = load('hkdf-vwk-v1.json')
assert h(hv['infoHex']) == b'empty/vwk/v1'
hv['outputHex'] = hkdf(h(hv['ikmHex']), h(hv['saltHex']), h(hv['infoHex']), hv['outputBytes']).hex()
save('hkdf-vwk-v1.json', hv)

# Raw XChaCha20-Poly1305
xv = load('xchacha20-poly1305-v1.json')
xv['ciphertextHex'] = xchacha_encrypt(h(xv['keyHex']), h(xv['nonceHex']), h(xv['aadHex']), h(xv['plaintextHex'])).hex()
save('xchacha20-poly1305-v1.json', xv)

# Object envelope
ev = load('vault-object-envelope-v1.json')
aad_vector = load('vault-object-aad-v1.json')
aad = h(ev['aadHex'])
assert aad == h(aad_vector['aadHex']) and b'empty.vault/1' in aad
vwk = hkdf(h(ev['vrkHex']), h(aad_vector['vaultIdHex']), b'empty/vwk/v1')
wrapped = xchacha_encrypt(vwk, h(ev['wrappedNonceHex']), aad + b'\0dek', h(ev['dekHex']))
payload = xchacha_encrypt(h(ev['dekHex']), h(ev['payloadNonceHex']), aad + b'\0payload', h(ev['payloadCborHex']))
envelope_artifact = frame(1, cbor_map([
    (1, cbor_bstr(aad)),
    (2, cbor_map([(1, cbor_bstr(h(ev['wrappedNonceHex']))), (2, cbor_bstr(wrapped))])),
    (3, cbor_map([(1, cbor_bstr(h(ev['payloadNonceHex']))), (2, cbor_bstr(payload))])),
]))
ev.update(vwkHex=vwk.hex(), wrappedCiphertextHex=wrapped.hex(), payloadCiphertextHex=payload.hex(),
          artifactHex=envelope_artifact.hex())
save('vault-object-envelope-v1.json', ev)

# Operation header: only ciphertext_hash (key 11, last entry) depends on the envelope bytes
ov = load('operation-header-v1.json')
artifact_hash = hashlib.sha256(envelope_artifact).digest()
old_header = h(ov['headerHex'])
tail = b'\x0b\x58\x20' + h(ov['ciphertextHashHex'])
assert old_header.endswith(tail) and b'empty.vault/1' in old_header
header = old_header[:-len(tail)] + b'\x0b\x58\x20' + artifact_hash
ov.update(ciphertextHashHex=artifact_hash.hex(), headerHex=header.hex())
save('operation-header-v1.json', ov)

# Signed operation
sv = load('signed-operation-v1.json')
seed, public = h(sv['secretSeedHex']), h(sv['publicKeyHex'])
signature = openssl_sign(seed, header)
assert sodium_verify(signature, header, public)
sv.update(headerHex=header.hex(), signatureHex=signature.hex(),
          artifactHex=frame(2, cbor_map([(1, cbor_bstr(header)), (2, cbor_bstr(signature))])).hex())
for case in sv['negativeCases']:
    builder = {'small-order-R': small_order_r_case, 'mixed-order-public-key': mixed_order_key_case}[case['name']]
    key, sig = builder(header)
    assert not sodium_verify(sig, header, key), case['name']
    case.update(publicKeyHex=key.hex(), signatureHex=sig.hex())
save('signed-operation-v1.json', sv)

# Sealed checkpoint
cv = load('checkpoint-v1.json')
checkpoint = h(cv['checkpointHex'])
assert b'empty.vault/1' in checkpoint
ck = hkdf(h(cv['vrkHex']), h(cv['vaultIdHex']), b'empty/checkpoint/v1')
mac = hmac.new(ck, checkpoint, hashlib.sha256).digest()
cv.update(checkpointKeyHex=ck.hex(), macHex=mac.hex(),
          artifactHex=frame(3, cbor_map([(1, cbor_bstr(checkpoint)), (2, cbor_bstr(mac))])).hex())
save('checkpoint-v1.json', cv)

# Key slots
kv = load('key-slot-v1.json')
vault_id, vrk = h(kv['vaultIdHex']), h(kv['vrkHex'])
argon = load('argon2id-v1.json')
pw = kv['password']
assert pw['argonOutputHex'] in json.dumps(argon), 'Argon2id output must come from argon2id-v1'


def slot_artifact(aad_bytes, nonce, ciphertext):
    return frame(4, cbor_map([(1, cbor_bstr(aad_bytes)), (2, cbor_bstr(nonce)), (3, cbor_bstr(ciphertext))]))


pw_kek = hkdf(h(pw['argonOutputHex']), vault_id, b'empty/password-kek/v1' + h(pw['slotIdHex']))
pw_ct = xchacha_encrypt(pw_kek, h(pw['nonceHex']), h(pw['aadHex']), vrk)
pw.update(kekHex=pw_kek.hex(), ciphertextHex=pw_ct.hex(),
          artifactHex=slot_artifact(h(pw['aadHex']), h(pw['nonceHex']), pw_ct).hex())

rc = kv['recovery']
secret = h(rc['secretHex'])
rc_kek = hkdf(secret, vault_id, b'empty/recovery-kek/v1' + h(rc['slotIdHex']))
rc_ct = xchacha_encrypt(rc_kek, h(rc['nonceHex']), h(rc['aadHex']), vrk)
rc_artifact = slot_artifact(h(rc['aadHex']), h(rc['nonceHex']), rc_ct)
data = b32(secret, 52)
check = b32(hashlib.sha256(b'empty/recovery-check/v1' + secret).digest()[:3], 4)
groups = [data[i:i + 4] for i in range(0, 52, 4)] + [check]
encoded = '-'.join(groups)
rc.update(kekHex=rc_kek.hex(), ciphertextHex=rc_ct.hex(), artifactHex=rc_artifact.hex(), encoded=encoded)

alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
bad_check = check[:3] + next(c for c in 'A7' if c != check[3])
bad_pad = alphabet[(alphabet.index(data[51]) & 0x10) | 1]  # same data bit, non-zero low 4 pad bits
kv['invalidRecoveryEncodings'] = [
    '-'.join(groups[:-1] + [bad_check]),                      # wrong checksum
    data[:51],                                                # too short
    data[:51] + bad_pad + '-' + check,                        # non-zero pad bits
    encoded + '-AAAA',                                        # too long
    '\u00a0'.join(groups),                                    # no-break space separator
    encoded[:-1] + 'ı',                                       # non-ASCII letter
    '　'.join(groups),                                    # Unicode ideographic space
    'A' * 129,                                                # over 128 bytes
]
kv['invalidArtifactsHex'] = {
    'trailingByte': (frame(4, rc_artifact[11:] + b'\x00')).hex(),
    'objectKind': (MAGIC + bytes([0, 1, 1]) + rc_artifact[7:]).hex(),
    'truncated': rc_artifact[:-1].hex(),
}
save('key-slot-v1.json', kv)

print(('out of date: ' if CHECK else 'updated: ') + (', '.join(changed) or 'nothing'))
sys.exit(1 if CHECK and changed else 0)
