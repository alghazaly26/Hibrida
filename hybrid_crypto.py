import base64
import hashlib
import os
import secrets
import struct
from math import gcd

# ---------- SHA256 ----------

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ---------- AES (128-bit CBC) ----------

S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

R_CON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _sub_word(word):
    return bytes(S_BOX[b] for b in word)


def _rot_word(word):
    return word[1:] + word[:1]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _key_expansion(key: bytes) -> list[bytes]:
    assert len(key) == 16
    words = [key[i: i + 4] for i in range(0, len(key), 4)]
    for i in range(4, 44):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = _xor_bytes(_sub_word(_rot_word(temp)), bytes([R_CON[i // 4], 0, 0, 0]))
        words.append(_xor_bytes(words[i - 4], temp))
    return [b''.join(words[4 * i:4 * i + 4]) for i in range(11)]


def _add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


def _sub_bytes(state):
    return [S_BOX[b] for b in state]


def _shift_rows(state):
    return [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11],
    ]


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1)


def _mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ _xtime(a[0] ^ a[1])
    a[1] ^= t ^ _xtime(a[1] ^ a[2])
    a[2] ^= t ^ _xtime(a[2] ^ a[3])
    a[3] ^= t ^ _xtime(a[3] ^ u)
    return a


def _mix_columns(state):
    return sum((_mix_single_column(list(state[i:i + 4])) for i in range(0, 16, 4)), [])


def aes_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    state = list(block)
    state = _add_round_key(state, round_keys[0])
    for r in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])
    return bytes(state)


def aes_decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    raise NotImplementedError("AES decryption is not implemented in this minimal example")


def pad(data: bytes) -> bytes:
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    return data[:-padding_len]


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = secrets.token_bytes(16)
    round_keys = _key_expansion(key)
    plaintext = pad(plaintext)
    ciphertext = bytearray(iv)
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = bytes(a ^ b for a, b in zip(plaintext[i:i + 16], prev))
        encrypted = aes_encrypt_block(block, round_keys)
        ciphertext.extend(encrypted)
        prev = encrypted
    return bytes(ciphertext)


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("Invalid ciphertext length")
    iv = ciphertext[:16]
    round_keys = _key_expansion(key)
    plaintext = bytearray()
    prev = iv
    for i in range(16, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        # decryption is not implemented here; this function is a placeholder
        raise NotImplementedError("AES decryption is not implemented in this minimal example")
    return unpad(bytes(plaintext))

# ---------- RSA ----------

def _miller_rabin(n: int, rounds: int = 8) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    return _miller_rabin(n, rounds=10)


def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits - 2) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def modinv(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def generate_rsa_keypair(bits: int = 1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return {
        "n": n,
        "e": e,
        "d": d,
        "p": p,
        "q": q,
    }


def rsa_encrypt(message: bytes, pubkey: dict) -> bytes:
    m = int.from_bytes(message, "big")
    if m >= pubkey["n"]:
        raise ValueError("Message too large for key")
    c = pow(m, pubkey["e"], pubkey["n"])
    return c.to_bytes((pubkey["n"].bit_length() + 7) // 8, "big")


def rsa_decrypt(ciphertext: bytes, privkey: dict) -> bytes:
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, privkey["d"], privkey["n"])
    return m.to_bytes((privkey["n"].bit_length() + 7) // 8, "big").lstrip(b"\x00")


def rsa_sign(message: bytes, privkey: dict) -> bytes:
    h = int.from_bytes(hashlib.sha256(message).digest(), "big")
    s = pow(h, privkey["d"], privkey["n"])
    return s.to_bytes((privkey["n"].bit_length() + 7) // 8, "big")


def rsa_verify(message: bytes, signature: bytes, pubkey: dict) -> bool:
    h = int.from_bytes(hashlib.sha256(message).digest(), "big")
    s = int.from_bytes(signature, "big")
    h2 = pow(s, pubkey["e"], pubkey["n"])
    return h == h2

# ---------- Schnorr signature ----------

def generate_schnorr_parameters(bit_length: int = 256):
    q = generate_prime(bit_length)
    p = 2 * q + 1
    while not is_prime(p):
        q = generate_prime(bit_length)
        p = 2 * q + 1
    g = 2
    while pow(g, q, p) == 1:
        g += 1
    return p, q, g


def generate_schnorr_keypair(p: int, q: int, g: int):
    x = secrets.randbelow(q - 1) + 1
    y = pow(g, x, p)
    return {"p": p, "q": q, "g": g, "x": x, "y": y}


def schnorr_sign(message: bytes, keypair: dict) -> tuple[int, int]:
    p, q, g, x = keypair["p"], keypair["q"], keypair["g"], keypair["x"]
    k = secrets.randbelow(q - 1) + 1
    r = pow(g, k, p)
    e = int.from_bytes(hashlib.sha256(r.to_bytes((p.bit_length() + 7) // 8, "big") + message).digest(), "big") % q
    s = (k + x * e) % q
    return r, s


def schnorr_verify(message: bytes, signature: tuple[int, int], pubkey: dict) -> bool:
    p, q, g, y = pubkey["p"], pubkey["q"], pubkey["g"], pubkey["y"]
    r, s = signature
    e = int.from_bytes(hashlib.sha256(r.to_bytes((p.bit_length() + 7) // 8, "big") + message).digest(), "big") % q
    left = pow(g, s, p)
    right = (r * pow(y, e, p)) % p
    return left == right

# ---------- Diffie-Hellman ----------

DH_P = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
    "FFFFFFFF FFFFFFFF".replace(" ", ""), 16
)
DH_G = 2

def dh_generate_private() -> int:
    return secrets.randbelow(DH_P - 2) + 2


def dh_compute_shared(private_key: int, public_key: int) -> int:
    return pow(public_key, private_key, DH_P)


def dh_public_key(private_key: int) -> int:
    return pow(DH_G, private_key, DH_P)

# ---------- Steganography LSB ----------

def _text_to_bits(text: str) -> list[int]:
    bits = []
    data = text.encode("utf-8")
    for byte in data:
        bits.extend([(byte >> i) & 1 for i in reversed(range(8))])
    return bits


def _bits_to_text(bits: list[int]) -> str:
    bytes_out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        bytes_out.append(byte)
    return bytes_out.decode("utf-8", errors="replace")


def embed_text_in_bmp(input_path: str, output_path: str, message: str):
    with open(input_path, "rb") as f:
        data = bytearray(f.read())
    if data[:2] != b"BM":
        raise ValueError("Input is not a BMP file")
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    bits = _text_to_bits(message)
    length_bits = [(len(bits) >> i) & 1 for i in reversed(range(32))]
    bits = length_bits + bits
    if pixel_offset + len(bits) > len(data):
        raise ValueError("BMP image is too small for message")
    for i, bit in enumerate(bits):
        data[pixel_offset + i] = (data[pixel_offset + i] & 0xFE) | bit
    with open(output_path, "wb") as f:
        f.write(data)


def extract_text_from_bmp(input_path: str) -> str:
    with open(input_path, "rb") as f:
        data = f.read()
    if data[:2] != b"BM":
        raise ValueError("Input is not a BMP file")
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    length_bits = [data[pixel_offset + i] & 1 for i in range(32)]
    length = 0
    for bit in length_bits:
        length = (length << 1) | bit
    message_bits = [data[pixel_offset + 32 + i] & 1 for i in range(length)]
    return _bits_to_text(message_bits)

# ---------- Demonstration / Use Case ----------

def _preview_hex(data: bytes, length: int = 32) -> str:
    text = data.hex()
    if len(text) <= length * 2:
        return text
    return text[:length * 2] + "..."


def _preview_base64(data: bytes, length: int = 32) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    if len(encoded) <= length:
        return encoded
    return encoded[:length] + "..."


def demo():
    print("=== Hybrid Cryptography Demo ===")
    print("Nama: al ghazali | NIM: 231111051")
    print("-------------------------------------------")

    message = b"Data rahasia dari Al Ghazali dengan NIM 231111051."
    print("1) Pesan asli")
    print("   Plaintext:", message)
    print("   Panjang pesan:", len(message), "byte")
    print("   SHA256 hash:", sha256_hash(message))
    print()

    print("2) Enkripsi simetris AES-128 CBC")
    aes_key = secrets.token_bytes(16)
    ciphertext = aes_encrypt(message, aes_key)
    print("   AES key:", aes_key.hex())
    print("   Ciphertext length:", len(ciphertext), "byte")
    print("   Ciphertext preview:", _preview_hex(ciphertext, 24))
    print("   Ciphertext preview (Base64):", _preview_base64(ciphertext, 48))
    print("   Keterangan: AES menggunakan IV acak di blok pertama")
    print()

    print("3) Pembungkus kunci dengan RSA")
    rsa_keys = generate_rsa_keypair(512)
    rsa_pub = {"n": rsa_keys["n"], "e": rsa_keys["e"]}
    encrypted_key = rsa_encrypt(aes_key, rsa_pub)
    decrypted_key = rsa_decrypt(encrypted_key, rsa_keys)
    print("   RSA modulus size:", rsa_keys['n'].bit_length(), "bit")
    print("   RSA publik exponent:", rsa_keys['e'])
    print("   AES key terenkripsi (hex preview):", _preview_hex(encrypted_key, 24))
    print("   AES key terenkripsi (Base64 preview):", _preview_base64(encrypted_key, 48))
    print("   Kunci AES berhasil didekripsi kembali:", decrypted_key == aes_key)
    print()

    print("4) Tanda tangan Schnorr")
    schnorr_params = generate_schnorr_parameters(160)
    schnorr_keys = generate_schnorr_keypair(*schnorr_params)
    signature = schnorr_sign(message, schnorr_keys)
    verified = schnorr_verify(message, signature, schnorr_keys)
    print("   Parameter Schnorr:")
    print("     p bit length:", schnorr_params[0].bit_length())
    print("     q bit length:", schnorr_params[1].bit_length())
    print("   Public key y (hex preview):", hex(schnorr_keys['y'])[:66], "...")
    print("   Signature r (hex preview):", hex(signature[0])[:66], "...")
    print("   Signature s (hex preview):", hex(signature[1])[:66], "...")
    print("   Verifikasi tanda tangan Schnorr:", verified)
    print()

    print("5) Pertukaran kunci Diffie-Hellman")
    alice_priv = dh_generate_private()
    bob_priv = dh_generate_private()
    alice_pub = dh_public_key(alice_priv)
    bob_pub = dh_public_key(bob_priv)
    alice_shared = dh_compute_shared(alice_priv, bob_pub)
    bob_shared = dh_compute_shared(bob_priv, alice_pub)
    print("   Alice publik key (hex preview):", hex(alice_pub)[:66], "...")
    print("   Bob publik key (hex preview):", hex(bob_pub)[:66], "...")
    print("   Shared secret sama:", alice_shared == bob_shared)
    shared_hash = sha256_hash(alice_shared.to_bytes((alice_shared.bit_length() + 7) // 8, "big"))
    print("   Shared secret SHA256:", shared_hash)
    print()

    print("6) Steganografi LSB")
    print("   Gunakan fungsi embed_text_in_bmp() untuk menyisipkan pesan teks ke BMP.")
    print("   Gunakan fungsi extract_text_from_bmp() untuk mengambil kembali pesan tersembunyi.")
    print("-------------------------------------------")
    print("Demo selesai. Output di atas menunjukkan semua langkah kriptografi dalam bahasa yang lebih jelas.")


if __name__ == "__main__":
    demo()
