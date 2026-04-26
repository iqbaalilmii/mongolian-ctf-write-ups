# CTF Writeup: MemHunt Flag 1
**Category:** Memory Forensics  
**Flag:** `HZ2023{F1r$T_Warm1p_fl@g_0x123456789}`

---

## Deskripsi

Tantangan ini merupakan soal memory forensics berbasis Linux. Kita diberikan sebuah file memory dump (`file.dump`) dan diminta untuk menemukan flag yang tersembunyi di dalamnya. Tools utama yang digunakan adalah **Volatility 3**.

---

## Rekonstruksi Kejadian

Sebelum masuk ke langkah-langkah teknis, berikut adalah gambaran besar apa yang terjadi di sistem berdasarkan artefak yang ditemukan:

1. User `zangi` (UID 1000) login via console lokal dan SSH
2. Attacker clone repo **LiME** (Linux Memory Extractor), compile, lalu dump memory ke `/home/zangi/zangi/dump.mem`
3. Setelah dump selesai, attacker `sudo su` ke root lalu **menghapus direktori LiME** (`rm -rf LiME/`) untuk menghilangkan jejak
4. Di sesi root kedua, attacker **membersihkan bash history** (`cat /dev/null > ~/.bash_history`)
5. Attacker clone repo **Volatility Ubuntu 1804 Profile** yang ternyata berisi script Python tersembunyi
6. Script tersebut berisi URL Pastebin tempat flag di-exfiltrate
7. Terakhir, attacker load **rootkit Diamorphine** via `insmod` untuk menyembunyikan aktivitasnya

---

## Langkah-Langkah Penyelesaian

### Step 1: Analisis Bash History

```bash
vol3 -f file.dump linux.bash
```

Output mencurigakan dari beberapa PID:

| PID | Command | Keterangan |
|-----|---------|------------|
| 1962 | `git clone https://github.com/504ensicsLabs/LiME.git` | Clone LiME untuk dump memory |
| 1962 | `insmod ./lime-4.15.0-213-generic.ko "path=/home/zangi/zangi/dump.mem format=lime"` | Eksekusi dump memory |
| 2685 | `rm -rf LiME/` | Hapus jejak |
| 2873 | `cat /dev/null > ~/.bash_history` | Bersihkan history |
| 2873 | `git clone https://github.com/iderbukh/Volatility_Ubuntu1804_Profile.git` | Clone repo profil Volatility |


---

### Step 2: Analisis Process List

```bash
vol3 -f file.dump linux.pslist
vol3 -f file.dump linux.psaux
```

Dari `psaux` ditemukan command lengkap proses `insmod`:

```
9637  2873  insmod  insmod ./lime-4.15.0-213-generic.ko path=/home/zangi/zangi/dump.mem format=lime
```

Ini mengkonfirmasi lokasi output dump memory: `/home/zangi/zangi/dump.mem`

Juga terlihat pola eskalasi privilege:
```
1802  bash  →  2683  sudo su  →  2684  su  →  2685  bash (root)
2856  bash  →  2871  sudo su  →  2872  su  →  2873  bash (root)
```

---

### Step 3: Deteksi Rootkit

```bash
vol3 -f file.dump linux.lsmod
vol3 -f file.dump linux.check_modules
```

`linux.lsmod` menampilkan modul normal. Namun `linux.check_modules` menemukan modul **tersembunyi**:

```
0xffffc077f0d0  diamorphine  0x4000  OOT_MODULE,UNSIGNED_MODULE
```

**[Diamorphine](https://github.com/m0nad/Diamorphine)** adalah LKM rootkit Linux yang terkenal dengan kemampuan:
- Menyembunyikan dirinya dari `lsmod`
- Menyembunyikan proses tertentu
- Privilege escalation (via signal 64)

Dikonfirmasi juga oleh `linux.hidden_modules`:
```
0xffffc077f040  diamorphine  0x4000  OOT_MODULE,UNSIGNED_MODULE
```

---

### Step 4: Investigasi File di Pagecache

```bash
vol3 -f file.dump linux.pagecache.Files | grep -i zangi
```

Ditemukan file-file menarik di direktori zangi:

```
/home/zangi/zangi/dump.mem                               → 945,314,880 bytes
/home/zangi/Volatility_Ubuntu1804_Profile/test.py        → 1005 bytes
/home/zangi/LiME/src/lime-4.15.0-213-generic.ko          → 20,896 bytes
```

File `test.py` berukuran 1005 bytes di dalam repo Volatility Profile sangat mencurigakan — kenapa ada Python script di sana?

---

### Step 5: Recovery Filesystem dari Memory

```bash
mkdir -p ./recovered
vol3 -f file.dump -o ./recovered linux.pagecache.RecoverFs
cd recovered
tar -xzf recovered_fs.tar.gz
```

Setelah diekstrak, ditemukan struktur direktori `/home/zangi/`. Namun banyak file yang 0 bytes karena kontennya tidak ter-cache di memory saat dump dilakukan.

---

### Step 6: Ekstrak Git Objects

Meski `test.py` ter-recover sebagai file kosong, konten aslinya masih bisa ditemukan melalui **git objects** yang ter-cache di memory:

```bash
cd 262cd342-5473-4dde-8b29-fff35b4a0bb8/home/zangi/Volatility_Ubuntu1804_Profile/.git/objects
```
```
for f in $(find . -type f -size +0c); do
    echo "=== $f ==="
    python3 -c "import zlib,sys; print(zlib.decompress(open('$f','rb').read()))" 2>/dev/null
done
```

Git menyimpan file sebagai objek terkompresi zlib. Hasil dekompresi:

**Object `b1/8e0ebc...`** → Ini adalah blob dari `test.py`:
<img width="1600" height="940" alt="image" src="https://github.com/user-attachments/assets/e0881fc0-ee42-459b-8099-05fde8dede45" />

**Object `49/53b0d4...`** → Commit message:
```
commit 679
author Id3r <iderbukh@must.edu.mn>
...
test
```

**Object `3c/3701e5...`** → Tree object menunjukkan file di repo:
```
100644 Ubuntu18.04_volatility_profile
100644 Ubuntu1804.zip
100644 req.py
```

---

### Step 7: Akses URL Pastebin

Dari komentar di `test.py` ditemukan URL:

```
https://pastebin.com/gtuG2gkt
```

```bash
curl https://pastebin.com/raw/gtuG2gkt
```

Konten Pastebin (diunggah oleh user **ID3RE** pada 13 September 2023):

```
HZ2023{F1r$T_Warm1p_fl@g_0x123456789}
```

---

## Flag

```
HZ2023{F1r$T_Warm1p_fl@g_0x123456789}
```

---

## Timeline Lengkap

```
2023-09-11 07:58  → User zangi aktif di console lokal (PID 1802)
2023-09-11 08:02  → SSH masuk (PID 1962): clone LiME, install make, compile
2023-09-11 08:04  → sudo su root (PID 2685): rm -rf LiME/, hapus jejak
2023-09-14 06:26  → Sistem boot ulang
2023-09-14 06:34  → SSH masuk lagi (PID 1962 → sesi baru)
2023-09-14 06:37  → SSH masuk kedua (PID 2856): sudo su root (PID 2873)
2023-09-14 06:42  → Bersihkan bash history
2023-09-14 06:43  → Clone Volatility_Ubuntu1804_Profile (berisi test.py + URL Pastebin)
2023-09-14 06:43  → mkdir zangi (buat direktori output dump)
2023-09-14 06:44  → insmod lime → dump memory ke /home/zangi/zangi/dump.mem
2023-09-14 06:44  → Load rootkit Diamorphine
```

---

## Tools yang Digunakan

- **Volatility 3** — Memory forensics framework
- **Python 3** — Dekompresi git objects (zlib)
- **strings / grep** — Pencarian pattern di binary
- **Browser / curl** — Akses URL Pastebin

---

## Pelajaran dari Soal Ini

1. **Bash history bisa di-clear, tapi volatility tetap bisa recover** dari memory buffer
2. **Rootkit Diamorphine** tersembunyi dari `lsmod` biasa, tapi terdeteksi oleh `linux.check_modules`
3. **Git objects** menyimpan konten file dalam format zlib terkompresi — bahkan file yang sudah di-overwrite bisa di-recover dari git object store
4. **Pagecache Linux** menyimpan file yang baru-baru ini diakses di memory — sangat berguna untuk forensics
5. Attacker menggunakan **Pastebin sebagai C2/exfiltration channel** yang tersembunyi di dalam komentar kode

---

*Writeup by: Iqbal Ilmi  
*Event: HZ2023 CTF*
