# CTF Writeup: Secret Note
**Event:** Харуул Занги 2024 (ctf.mn)  
**Category:** Forensics  
**Points:** 945  
**Author:** Id3r

---

## Description

> "I've old damaged disk that contain my developed program. Can you recover my program and analyze it?"

---

## Overview

Tantangan ini melibatkan analisis disk image (`.e01`), ekstraksi APK Android dari dalamnya, reverse engineering kode Java hasil decompile, dan akhirnya dekripsi AES-CBC untuk mendapatkan flag.

**Flag:** `HZ2024{S3cCoApp_IziIT_H4rD_T0_F!Nd}`

---

## Step 1: Analisis Disk Image

File yang diberikan adalah `finaldd.e01`, sebuah disk image format EnCase E01. Kita gunakan tool forensics `fls` dari Sleuth Kit untuk melihat isi filesystem:

```bash
fls -r finaldd.e01
```

Dari output, terlihat beberapa direktori menarik:
- `0319/CVE-2023-38646` — exploit Metabase RCE
- `jenkins/CVE-2024-23897` — exploit Jenkins arbitrary file read
- `impacket/` — toolkit Windows network exploitation
- `android/fridump` — memory dumper Android via Frida
- `android/LiME` — Linux Memory Extractor (kernel module)
- **`mydev.apk`** (inode 12) ← **target utama!**

File APK diekstrak menggunakan `icat`:

```bash
icat finaldd.e01 12 > mydev.apk
```

---

## Step 2: Decompile APK

APK di-decompile menggunakan **jadx**:

```bash
jadx -d out_folder mydev.apk
```

Dari `AndroidManifest.xml`, ditemukan package utama `mn.test.seccoapp` dengan activity mencurigakan:

```xml
<activity android:name="mn.test.seccoapp.ui.login.S3rR3t__C0nT3nT" android:exported="false"/>
```

Struktur source code yang relevan:
```
sources/mn/test/seccoapp/
├── MainActivity.java
├── data/
│   ├── LoginDataSource.java
│   └── LiveLiterals$LoginDataSourceKt.java
└── ui/login/
    ├── LoginFragment.java          ← Key Part 1
    ├── LoginSecondFragment.java    ← Key Part 2
    ├── LoginThirdFragment.java     ← Key Part 3
    └── S3rR3t__C0nT3nT.java       ← Secret Activity
```

---

## Step 3: Menemukan AES Key

Pada ketiga fragment login, ditemukan variabel private key yang tersembunyi dengan nama yang sangat deskriptif:

**`LoginFragment.java`** — `pRiv_K3Y_StRt` (Start):
```java
private String pRiv_K3Y_StRt = "jKdxc";
```

**`LoginSecondFragment.java`** — `pRiv_K3Y_m1D` (Mid):
```java
private String pRiv_K3Y_m1D = "GqNrFZ";
```

**`LoginThirdFragment.java`** — `pRiv_K3Y_EИD` (End):
```java
private String pRiv_K3Y_EИD = "YnqLm";
```

Ketiga bagian digabung secara berurutan (Start → Mid → End):

```
AES Key = "jKdxc" + "GqNrFZ" + "YnqLm" = "jKdxcGqNrFZYnqLm"
```

Perhatikan bahwa panjang key tepat **16 bytes** → ini adalah **AES-128 key**!

---

## Step 4: Menemukan Ciphertext

Di layout `activity_s3r_r3t_c0n_t3n_t.xml` (activity rahasia), terdapat 6 TextView dengan teks hardcoded:

```xml
<TextView android:text="TggBtXpN"/>
<TextView android:text="HZr/YmbRI"/>
<TextView android:text="u1f6LOzIH9/+"/>
<TextView android:text="9pDSL63u6x"/>
<TextView android:text="UGtX0x4OoJB2"/>
<TextView android:text="nA6rawx2Z3aH1"/>
```

Karakter `/` dan `+` mengindikasikan **Base64**. Keenam string digabung lalu di-decode:

```python
strings = ["TggBtXpN", "HZr/YmbRI", "u1f6LOzIH9/+", "9pDSL63u6x", "UGtX0x4OoJB2", "nA6rawx2Z3aH1"]
all_b64 = "".join(strings)  # 64 chars
ciphertext = base64.b64decode(all_b64 + "==")  # 48 bytes
```

Hasilnya: **48 bytes** = 3 blok AES (masing-masing 16 bytes).

---

## Step 5: Menemukan IV

Terdapat **dua clue** yang mengarah ke IV:

### Clue 1 — `strings.xml`
```xml
<string name="prompt_email">IV B3l0W</string>
```
"IV B3l0W" = **"IV Below"** → IV tersembunyi di bawah (somewhere below in the layout).

### Clue 2 — `fragment_login.xml`
Di layout fragment login pertama, terdapat TextView dengan `visibility="gone"` (tidak terlihat user):

```xml
<TextView
    android:visibility="gone"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="1e5d706734492443"/>
```

String `"1e5d706734492443"` panjangnya tepat **16 karakter** → ini adalah **IV** (sebagai ASCII string)!

### Clue 3 — `fragment_login.xml` (bonus)
```
435, SI-B-SI 1s uZ3D f0r 3nKrYptI0И
```
Dibaca dalam leet speak: **"AES, CBC is used for encryption"** → konfirmasi mode enkripsi **AES-CBC**.

---

## Step 6: Dekripsi

Dengan semua bahan terkumpul:

| Parameter | Nilai |
|-----------|-------|
| Algoritma | AES-128-CBC |
| Key | `jKdxcGqNrFZYnqLm` (16 bytes) |
| IV | `1e5d706734492443` (16 bytes ASCII) |
| Ciphertext | Base64 decode dari 6 TextView (48 bytes) |

<img width="1919" height="951" alt="image" src="https://github.com/user-attachments/assets/b5738594-d1cb-4ff4-9d4e-a5a85c0bb11f" />

## Flag

```
HZ2024{S3cCoApp_IziIT_H4rD_T0_F!Nd}
```

---

## Summary

```
Disk Image (E01)
    └── icat → mydev.apk
                └── jadx decompile
                        ├── LoginFragment.java       → Key Part 1: "jKdxc"
                        ├── LoginSecondFragment.java → Key Part 2: "GqNrFZ"  
                        ├── LoginThirdFragment.java  → Key Part 3: "YnqLm"
                        │                              = AES Key: "jKdxcGqNrFZYnqLm"
                        ├── fragment_login.xml       → IV: "1e5d706734492443" (hidden)
                        │                            → Hint: "AES-CBC is used"
                        ├── strings.xml              → Hint: "IV B3l0W"
                        └── activity_s3r_r3t_c0n_t3n_t.xml
                                └── 6 TextViews → Base64 Ciphertext (48 bytes)
                                        └── AES-128-CBC Decrypt
                                                └── HZ2024{S3cCoApp_IziIT_H4rD_T0_F!Nd}
```

**Tools yang digunakan:**
- `fls` / `icat` (Sleuth Kit) — analisis dan ekstraksi disk image
- `jadx` — decompile APK Android
- `Python` + `pycryptodome` — dekripsi AES-CBC
