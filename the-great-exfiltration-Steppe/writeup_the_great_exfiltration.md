# Writeup: The Great Exfiltration of the Steppe
**CTF:** Харуул Занги 2025  
**Category:** Forensics  
**Points:** 724  
**Flag:** `HZ2025{s0-G00d.c0n62475}`

---

## Daftar Isi
1. [Deskripsi Soal](#1-deskripsi-soal)
2. [File yang Diberikan](#2-file-yang-diberikan)
3. [Big Picture — Apa yang Terjadi?](#3-big-picture--apa-yang-terjadi)
4. [Step 1 — Baca & Pahami Kode Malware](#4-step-1--baca--pahami-kode-malware-777py)
5. [Step 2 — Parse aescache.bin](#5-step-2--parse-aescachebin)
6. [Step 3 — Parse id_rsa_priv.xml](#6-step-3--parse-id_rsa_privxml)
7. [Step 4 — Analisis PCAP](#7-step-4--analisis-challenge-pcapng)
8. [Step 5 — Decrypt Semua Bagian](#8-step-5--decrypt-semua-bagian)
9. [Step 6 — Gabungkan Flag](#9-step-6--gabungkan-flag)
10. [Script Solver Lengkap](#10-script-solver-lengkap)

---

## 1. Deskripsi Soal

> *The year is 1227… or is it 2027? Whispers spread across the steppes that Genghis Khan has returned — but not with horsemen and bows. Instead, his Cyber Horde rides the waves of the Internet, launching raids across the digital Silk Road.*
>
> *Your mission is to stop one of his elite cyber-warriors. Intelligence suggests that the Horde has stolen a flag of power and exfiltrated it piece by piece using covert channels. Our monitoring systems captured strange traffic, but the data is fragmented and encrypted. Luckily every artifact is collected and presented to you. Good luck!*

Kata kunci dari deskripsi: **"exfiltrated piece by piece"** dan **"every artifact is collected"**. Ini petunjuk bahwa:
- Flag dibagi menjadi beberapa bagian
- Semua file yang dibutuhkan untuk solve sudah dikasih (kita tidak perlu brute force apapun)

---

## 2. File yang Diberikan

Setelah extract `challenge.zip`, kita mendapat:

```
challenge/
├── 777.py           ← Kode malware (obfuscated)
├── aescache.bin     ← Berisi AES key dan IV (56 bytes)
├── challenge.pcapng ← Capture traffic jaringan
├── id_rsa_priv.xml  ← RSA private key format XML
└── id_rsa_pub.xml   ← RSA public key format XML
```

---

## 3. Big Picture — Apa yang Terjadi?

Sebelum masuk ke detail teknis, mari pahami gambaran besarnya dulu.

Si attacker (malware `777.py`) mencuri sebuah flag, lalu **memecahnya jadi 3 bagian** dan mengirim tiap bagian lewat protokol jaringan yang berbeda, dengan enkripsi yang berbeda pula:

```
FLAG: "HZ2025{s0-G00d.c0n62475}"
         │
         ▼
   ┌─────────────┐
   │  Split 3    │
   └─────────────┘
         │
    ┌────┴────────────────┐
    │                     │
    ▼                     ▼                     ▼
"HZ2025{s"          "0-G00d.c"           "0n62475}"
    │                     │                     │
    │ RSA encrypt         │ AES encrypt         │ Base64 encode
    ▼                     ▼                     ▼
[256 bytes]           [16 bytes]           "MG42MjQ3NX0="
    │                     │                     │
    │ via ICMP            │ via TCP             │ via UDP
    ▼                     ▼                     ▼
 Packet 1             Packet 6             Packet 10
```

Kita sebagai defender punya semua artifactnya, jadi kita bisa **balik arah** proses ini untuk mendapatkan flag.

---

## 4. Step 1 — Baca & Pahami Kode Malware (`777.py`)

### Obfuscation

Kode `777.py` di-obfuscate dengan cara mengganti semua nama variabel/fungsi menjadi kombinasi huruf `I` (i besar) dan `l` (L kecil) yang sangat mirip. Contoh:

```python
lllllllllllllll  = Exception
llllllllllllllI  = int
lllllllllllllIl  = open
llllllllllllIlI  = len
lllllllllllIlll  = print
```

Meski terlihat menakutkan, logika programnya tetap bisa dibaca kalau kita trace dari fungsi utama.

### Fungsi Utama

Fungsi main (`llIIIIIIlIIllIlIIl`) melakukan langkah-langkah berikut:

#### ① Generate RSA Key Pair

```python
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
```

Key pair ini disimpan ke `id_rsa_priv.xml` dan `id_rsa_pub.xml` dalam format XML Microsoft (RSAKeyValue). **Inilah kesalahan fatal si attacker** — private key disimpan di mesin korban dan ikut ter-capture.

#### ② Generate AES Key + IV

```python
aes_key = urandom(32)  # 32 bytes = 256-bit key
aes_iv  = urandom(16)  # 16 bytes = 128-bit IV
```

Disimpan ke `aescache.bin` dengan format:
```
[4 bytes: panjang key] + [32 bytes: key] + [4 bytes: panjang IV] + [16 bytes: IV]
```

**Ini kesalahan kedua si attacker** — key AES juga tersimpan di mesin korban.

#### ③ Split Flag Jadi 3 Bagian

Fungsi `IlllIIlIlIlllIlIII(flag)` membagi string flag menjadi 3 potongan sama rata:

```python
from math import ceil

def split_3(s):
    chunk = ceil(len(s) / 3)
    return [
        s[0*chunk : 1*chunk],
        s[1*chunk : 2*chunk],
        s[2*chunk : 3*chunk],
    ]

# Contoh:
split_3("HZ2025{s0-G00d.c0n62475}")
# chunk = ceil(24/3) = 8
# → ["HZ2025{s", "0-G00d.c", "0n62475}"]
```

#### ④ Enkripsi & Kirim Tiap Bagian

| Part | Isi | Enkripsi | Protokol |
|------|-----|----------|----------|
| 0 | `"HZ2025{s"` | RSA PKCS1v15 (pakai public key) | ICMP Echo Request |
| 1 | `"0-G00d.c"` | AES-256-CBC + PKCS7 padding | TCP ke port 4445 |
| 2 | `"0n62475}"` | Base64 (bukan enkripsi, hanya encoding!) | UDP ke port 4444 |

---

## 5. Step 2 — Parse `aescache.bin`

### Kenapa formatnya aneh?

File ini **bukan** format standar. Si attacker nulis sendiri formatnya di kode. Kita harus baca kodenya dulu untuk tau cara parse-nya.

### Format Detail

File ini berukuran **56 bytes** persis. Breakdown tiap byte:

```
Byte 00-03: 20 00 00 00
            └─────────── Angka 32 dalam little-endian (= panjang AES key)

Byte 04-23: d7 c6 8a 16 c4 dc 67 66 e3 fb c7 0b fa 09 4b f9
            47 16 d5 18 66 62 3b fa ba 3a 18 57 e8 8f 4f f5
            └─────────────────────────────────────────────── 32 byte AES Key

Byte 24-27: 10 00 00 00
            └─────────── Angka 16 dalam little-endian (= panjang AES IV)

Byte 28-37: 3b 12 a3 5f 7b 3f 05 87 7e 88 1c a0 a2 66 f3 71
            └─────────────────────────────────────────────── 16 byte AES IV
```

### Apa itu Little-Endian?

Komputer menyimpan angka multi-byte dalam urutan tertentu. **Little-endian** artinya byte paling kecil (least significant) disimpan **duluan** (di alamat memori terkecil).

Contoh angka **32** = `0x00000020` dalam 4 byte:
```
Big-endian    : 00 00 00 20  ← byte terbesar duluan
Little-endian : 20 00 00 00  ← byte terkecil duluan
```

Python menggunakan `struct.unpack('<I', ...)` untuk baca little-endian:
- `<` = little-endian
- `I` = unsigned int 32-bit

### Kode Parse

```python
import struct

raw = open('aescache.bin', 'rb').read()

# Baca panjang key (4 byte pertama, little-endian)
klen = struct.unpack_from('<I', raw, 0)[0]   # → 32

# Ambil key-nya
aes_key = raw[4 : 4 + klen]                 # byte 4 s/d 35

# Baca panjang IV (4 byte setelah key)
ivlen = struct.unpack_from('<I', raw, 4 + klen)[0]  # → 16

# Ambil IV-nya
aes_iv = raw[4 + klen + 4 : 4 + klen + 4 + ivlen]  # byte 40 s/d 55

print(aes_key.hex())
# → d7c68a16c4dc6766e3fbc70bfa094bf94716d51866623bfaba3a1857e88f4ff5

print(aes_iv.hex())
# → 3b12a35f7b3f05877e881ca0a266f371
```

---

## 6. Step 3 — Parse `id_rsa_priv.xml`

### Format PEM vs Format XML

Kamu mungkin lebih familiar dengan RSA private key dalam format **PEM** yang terlihat seperti ini:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHABNT...
-----END RSA PRIVATE KEY-----
```

Tapi di soal ini, si attacker menyimpan key dalam format **XML Microsoft RSAKeyValue**. Isinya **sama persis**, cuma formatnya berbeda.

### Komponen Matematika RSA

RSA private key sebenarnya terdiri dari beberapa angka besar. Masing-masing angka ini di-encode sebagai Base64 dan disimpan dalam tag XML:

| Tag XML | Nama | Penjelasan |
|---------|------|------------|
| `<Modulus>` | n | Hasil kali p × q. Bagian dari public key juga. |
| `<Exponent>` | e | Selalu 65537 (`AQAB` dalam Base64). Bagian dari public key. |
| `<D>` | d | **Private exponent**. Ini kunci rahasianya untuk decrypt. |
| `<P>` | p | Bilangan prima besar pertama |
| `<Q>` | q | Bilangan prima besar kedua |
| `<DP>` | dp | d mod (p-1). Untuk mempercepat operasi. |
| `<DQ>` | dq | d mod (q-1). Untuk mempercepat operasi. |
| `<InverseQ>` | iqmp | q⁻¹ mod p. Untuk mempercepat operasi. |

Contoh sepotong isi XML-nya:
```xml
<RSAKeyValue>
  <Modulus>uGKlznqZ2xy6OhfHgfNs...</Modulus>
  <Exponent>AQAB</Exponent>
  <P>83FaL4HDv/Uiq+u1sh8V...</P>
  <Q>weVyAqRJUg9QikG6rd2r...</Q>
  <DP>1I9JxqdQSyB4WJKkAFYB...</DP>
  <DQ>nRdxNHS4NrTTswAn5/+l...</DQ>
  <InverseQ>Z2QXac5M6PoogLL0...</InverseQ>
  <D>Q4Hml+beTtFBQ4SySFtR...</D>
</RSAKeyValue>
```

### Cara Baca Nilai Base64 → Integer

Setiap nilai di XML di-encode Base64. Kita perlu convert ke integer besar (big-endian) untuk dipakai Python:

```python
from base64 import b64decode

def b64int(s):
    # 1. Decode Base64 → bytes
    raw_bytes = b64decode(s.strip())
    # 2. Interpret bytes sebagai integer big-endian
    return int.from_bytes(raw_bytes, 'big')

# Contoh: "AQAB" → 65537
b64int("AQAB")
# b64decode("AQAB") → b'\x01\x00\x01'
# int.from_bytes(b'\x01\x00\x01', 'big') → 65537 ✓
```

### Rakit Jadi Private Key Python

```python
import xml.etree.ElementTree as ET
from base64 import b64decode
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers
)
from cryptography.hazmat.backends import default_backend

def b64int(s):
    return int.from_bytes(b64decode(s.strip()), 'big')

# Parse XML
root = ET.fromstring(open('id_rsa_priv.xml').read())

# Ambil semua komponen
n    = b64int(root.find('Modulus').text)
e    = b64int(root.find('Exponent').text)   # = 65537
d    = b64int(root.find('D').text)
p    = b64int(root.find('P').text)
q    = b64int(root.find('Q').text)
dp   = b64int(root.find('DP').text)
dq   = b64int(root.find('DQ').text)
iqmp = b64int(root.find('InverseQ').text)

# Rakit jadi objek private key
pub_numbers  = RSAPublicNumbers(e=e, n=n)
priv_numbers = RSAPrivateNumbers(
    p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=iqmp,
    public_numbers=pub_numbers
)
private_key = priv_numbers.private_key(default_backend())

# Selesai! private_key siap dipakai untuk decrypt
```

---

## 7. Step 4 — Analisis `challenge.pcapng`

### Apa itu PCAPNG?

PCAPNG (Packet Capture Next Generation) adalah format file untuk menyimpan capture traffic jaringan. Kita bisa buka dengan Wireshark, atau parse manual dengan Python.

### Struktur PCAPNG

File PCAPNG terdiri dari **blok-blok** berurutan:

```
[Section Header Block (SHB)]     ← header file
[Interface Description Block]    ← info interface jaringan
[Enhanced Packet Block]          ← packet 1
[Enhanced Packet Block]          ← packet 2
...dst
```

Setiap Enhanced Packet Block (EPB) punya struktur:
```
Offset 0  : Block Type (4 byte) = 0x00000006
Offset 4  : Block Length (4 byte)
Offset 8  : Interface ID (4 byte)
Offset 12 : Timestamp High (4 byte)
Offset 16 : Timestamp Low (4 byte)
Offset 20 : Captured Length (4 byte)
Offset 24 : Original Length (4 byte)
Offset 28 : [Packet Data — ini yang kita mau]
```

### Packet yang Relevan

Dari 12 packet yang ada di pcap, hanya 3 yang mengandung data exfiltration:

#### Packet 1 — ICMP (Berisi Part 1, RSA Encrypted)

```
Protokol : ICMP
Type     : 8 (Echo Request)
ID       : 0xaaa1  ← identifier unik dari malware
Sequence : 1

ICMP Header (8 byte): 08 00 7d 14 aa a1 00 01
                       │    │    │     └── seq=1
                       │    │    └──────── id=0xaaa1
                       │    └───────────── checksum
                       └────────────────── type=8 (request)

ICMP Data (256 byte):
1a e1 9d 16 cd dc 30 9b 34 e5 d6 0b 6a 0e 2c 55
e2 26 45 86 88 b1 90 87 f2 97 1d fb 0a e7 54 10
... (256 bytes total)
```

Kenapa 256 byte? Karena RSA-2048 menghasilkan ciphertext **2048 bit = 256 byte** persis.

#### Packet 6 — TCP PSH (Berisi Part 2, AES Encrypted)

```
Protokol  : TCP
Source    : 192.168.213.132:56302
Dest      : 10.21.68.90:80
Flags     : PSH + ACK (0x18) ← PSH = ada data yang dikirim
TCP Payload (16 byte):
fc 9b 14 94 46 52 30 e2 2d 70 fd 5f af 55 f4 8f
```

Kenapa 16 byte? Karena AES block size = 128 bit = 16 byte. String `"0-G00d.c"` (8 karakter) di-pad PKCS7 menjadi 16 byte, lalu di-encrypt → hasilnya 16 byte.

#### Packet 10 — UDP (Berisi Part 3, Base64)

```
Protokol  : UDP
Source    : 192.168.213.132:49346
Dest      : 10.21.68.90:4445
UDP Payload (12 byte): 4d 47 34 32 4d 6a 51 33 4e 58 30 3d
```

Convert hex → ASCII: `MG42MjQ3NX0=`

Ini langsung Base64! Kita bisa verifikasi:
```
MG42MjQ3NX0=  →  base64 decode  →  0n62475}
```

---

## 8. Step 5 — Decrypt Semua Bagian

### Decrypt Part 1 — RSA PKCS1v15

RSA decryption sangat straightforward setelah kita punya private key:

```python
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

# part1_enc = 256 bytes dari ICMP payload
part1_enc = bytes.fromhex(
    '1ae19d16cddc309b34e5d60b6a0e2c55e226458688b19087'
    'f2971dfb0ae75410d42d784b0e5873764de92f16a1ccb6b3'
    '24978c8cff8659f5c9e5ac4d9f23879fd6ca94f2097aa275'
    '85ee2b13ac4b02cd819d78dc310db2448205b6a61c0581c2'
    'bbc4270a89353cf468917c359866d9172742e4441cda568a'
    'b85bb62a7c74599a1633c90f74f482583f40574cc5ea3beb'
    'a08fb44d76f95c41f74533885d03a286b177614c30f13d93'
    'accc23d2448138025a4a7d1ed9011948d32d67534a39cf96'
    '60201c22a3b51a9488ccebf5d818043d1f5e7a5778a6b650'
    '89e350c3e5c68ded6207888a07f49a4c1435fdc1d5334e26'
    'f9c5393782fcd5d4a39083f94bb07c44'
)

part1 = private_key.decrypt(part1_enc, PKCS1v15())
print(part1)  # → b'HZ2025{s'
```

### Decrypt Part 2 — AES-256-CBC

#### Apa itu PKCS7 Padding?

AES-CBC hanya bisa memproses data yang panjangnya kelipatan 16 byte (= 1 block). Tapi string `"0-G00d.c"` hanya 8 byte. Solusinya: **padding**.

PKCS7 padding bekerja seperti ini:
- Kekurangan berapa byte untuk mencapai kelipatan 16? → 16 - 8 = **8 byte**
- Tambahkan 8 byte, masing-masing berisi angka **8** (`\x08`)

```
Sebelum padding: 30 2d 47 30 30 64 2e 63
                 "0  -  G  0  0  d  .  c"

Sesudah padding: 30 2d 47 30 30 64 2e 63 08 08 08 08 08 08 08 08
                 "0  -  G  0  0  d  .  c" [8 bytes padding \x08]
```

Waktu decrypt, kita hapus padding-nya:
```python
pad_len = plain[-1]   # baca byte terakhir → 8
part2   = plain[:-pad_len]  # hapus 8 byte terakhir
```

#### Kode Decrypt AES

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

part2_enc = bytes.fromhex('fc9b1494465230e22d70fd5faf55f48f')

# Buat cipher AES-256-CBC
cipher = Cipher(
    algorithms.AES(aes_key),   # key 32 byte
    modes.CBC(aes_iv),          # IV 16 byte
    backend=default_backend()
)

# Decrypt
decryptor = cipher.decryptor()
plain = decryptor.update(part2_enc) + decryptor.finalize()
# plain = b'0-G00d.c\x08\x08\x08\x08\x08\x08\x08\x08'

# Hapus PKCS7 padding
pad_len = plain[-1]   # → 8
part2   = plain[:-pad_len]
print(part2)  # → b'0-G00d.c'
```

### Decode Part 3 — Base64

```python
from base64 import b64decode

part3_b64 = b'MG42MjQ3NX0='
part3 = b64decode(part3_b64).decode('utf-8')
print(part3)  # → '0n62475}'
```

Verifikasi manual:
```
M  G  4  2  M  j  Q  3  N  X  0  =
↓
(Base64 decode)
↓
30 6e 36 32 34 37 35 7d
"0  n  6  2  4  7  5  }"
```

---

## 9. Step 6 — Gabungkan Flag

```python
part1 = b'HZ2025{s'
part2 = b'0-G00d.c'
part3 = '0n62475}'

flag = part1.decode() + part2.decode() + part3
print(flag)
```

```
🚩 FLAG: HZ2025{s0-G00d.c0n62475}
```

---

## 10. Script Solver Lengkap

Simpan sebagai `solve.py`, taruh satu folder dengan semua file challenge, lalu jalankan:

```bash
pip install cryptography
python3 solve.py
```

```python
#!/usr/bin/env python3
"""
Writeup Solver: The Great Exfiltration of the Steppe
CTF: Харуул Занги 2025 | Category: Forensics

Files required (same directory):
  - challenge.pcapng
  - aescache.bin
  - id_rsa_priv.xml
"""

import struct
import xml.etree.ElementTree as ET
from base64 import b64decode
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

print("=" * 55)
print("  The Great Exfiltration — Solver")
print("=" * 55)

# ─────────────────────────────────────────────────────────
# STEP 1: Load RSA Private Key dari id_rsa_priv.xml
# ─────────────────────────────────────────────────────────
def b64int(s):
    """Convert Base64 string → big integer."""
    return int.from_bytes(b64decode(s.strip()), 'big')

root = ET.fromstring(open('id_rsa_priv.xml').read())
private_key = RSAPrivateNumbers(
    p    = b64int(root.find('P').text),
    q    = b64int(root.find('Q').text),
    d    = b64int(root.find('D').text),
    dmp1 = b64int(root.find('DP').text),
    dmq1 = b64int(root.find('DQ').text),
    iqmp = b64int(root.find('InverseQ').text),
    public_numbers = RSAPublicNumbers(
        e = b64int(root.find('Exponent').text),
        n = b64int(root.find('Modulus').text),
    )
).private_key(default_backend())
print("[+] RSA private key loaded dari id_rsa_priv.xml")

# ─────────────────────────────────────────────────────────
# STEP 2: Parse AES Key + IV dari aescache.bin
# Format: pack('<I', klen) + key + pack('<I', ivlen) + iv
# ─────────────────────────────────────────────────────────
raw  = open('aescache.bin', 'rb').read()
klen    = struct.unpack_from('<I', raw, 0)[0]
aes_key = raw[4 : 4 + klen]
ivlen   = struct.unpack_from('<I', raw, 4 + klen)[0]
aes_iv  = raw[4 + klen + 4 : 4 + klen + 4 + ivlen]
print(f"[+] AES Key ({klen}B): {aes_key.hex()}")
print(f"[+] AES IV  ({ivlen}B): {aes_iv.hex()}")

# ─────────────────────────────────────────────────────────
# STEP 3: Parse PCAPNG — ambil payload dari tiap packet
# ─────────────────────────────────────────────────────────
def parse_pcapng(path):
    """Parser minimal PCAPNG, return list of raw Ethernet frames."""
    data = open(path, 'rb').read()
    pkts, i = [], 0
    while i + 8 <= len(data):
        btype = struct.unpack_from('<I', data, i)[0]
        blen  = struct.unpack_from('<I', data, i + 4)[0]
        if blen < 12 or i + blen > len(data):
            break
        if btype == 0x00000006:  # Enhanced Packet Block
            cap_len = struct.unpack_from('<I', data, i + 20)[0]
            pkts.append(data[i + 28 : i + 28 + cap_len])
        i += blen
    return pkts

packets = parse_pcapng('challenge.pcapng')
print(f"[+] {len(packets)} packets ditemukan di pcap")

# ─────────────────────────────────────────────────────────
# STEP 4: Ekstrak payload berdasarkan protokol
# ─────────────────────────────────────────────────────────
part1_enc = part2_enc = part3_b64 = None

for idx, pkt in enumerate(packets):
    if len(pkt) < 14:
        continue
    eth_type = struct.unpack_from('>H', pkt, 12)[0]
    if eth_type != 0x0800:   # Bukan IPv4, skip
        continue

    ip_ihl = (pkt[14] & 0xF) * 4
    proto  = pkt[14 + 9]
    ip_end = 14 + ip_ihl

    if proto == 1 and part1_enc is None:     # ICMP
        icmp_payload = pkt[ip_end + 8:]
        if len(icmp_payload) >= 128:
            part1_enc = icmp_payload
            print(f"[+] Packet {idx+1}: ICMP payload {len(icmp_payload)} bytes (RSA ciphertext)")

    elif proto == 6:                          # TCP
        tcp_offset  = (pkt[ip_end + 12] >> 4) * 4
        tcp_payload = pkt[ip_end + tcp_offset:]
        if len(tcp_payload) > 0 and len(tcp_payload) % 16 == 0 and part2_enc is None:
            part2_enc = tcp_payload
            print(f"[+] Packet {idx+1}: TCP payload {len(tcp_payload)} bytes (AES ciphertext)")

    elif proto == 17 and part3_b64 is None:  # UDP
        udp_payload = pkt[ip_end + 8:]
        if len(udp_payload) > 0:
            part3_b64 = udp_payload
            print(f"[+] Packet {idx+1}: UDP payload → {udp_payload} (Base64)")

# ─────────────────────────────────────────────────────────
# STEP 5: Decrypt / Decode
# ─────────────────────────────────────────────────────────
print("\n[*] Mulai decrypt...")

# Part 1 — RSA PKCS1v15 Decrypt
part1 = private_key.decrypt(part1_enc, PKCS1v15())
print(f"[+] Part 1 (RSA/ICMP): {part1}")

# Part 2 — AES-256-CBC Decrypt + hapus PKCS7 padding
dec   = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv),
               backend=default_backend()).decryptor()
plain = dec.update(part2_enc) + dec.finalize()
part2 = plain[:-plain[-1]]   # hapus PKCS7 padding
print(f"[+] Part 2 (AES/TCP):  {part2}")

# Part 3 — Base64 Decode
part3 = b64decode(part3_b64.strip()).decode()
print(f"[+] Part 3 (B64/UDP):  {part3}")

# ─────────────────────────────────────────────────────────
# STEP 6: Gabungkan flag
# ─────────────────────────────────────────────────────────
flag = part1.decode() + part2.decode() + part3
print("\n" + "=" * 55)
print(f"  🚩  FLAG: {flag}")
print("=" * 55)
```

---

## Kesimpulan

Soal ini mengajarkan beberapa konsep penting:

1. **Membaca kode obfuscated** — nama variabel yang aneh tidak menghalangi kita memahami logika program
2. **Format file custom** — tidak semua file punya format standar; harus baca kodenya untuk tau cara parse
3. **RSA XML vs PEM** — private key bisa disimpan dalam berbagai format, isinya (komponen matematika) tetap sama
4. **AES-CBC** — memahami padding dan cara decrypt
5. **Analisis PCAPNG** — mengekstrak payload dari packet capture

**Pelajaran terpenting dari soal ini:** Si attacker melakukan kesalahan fatal dengan menyimpan **private key RSA** dan **AES key** di mesin yang sama dengan traffic yang di-capture. Dalam skenario nyata, key management yang buruk adalah salah satu kelemahan terbesar dalam sistem kriptografi.
