# DEX-ENC: Secure Image Steganography & Encryption

**DEX-ENC** adalah alat baris perintah (CLI) canggih yang menggabungkan enkripsi standar militer **AES-256-GCM** dengan teknik steganografi **Content-Adaptive LSB**. Alat ini memungkinkan Anda menyembunyikan data sensitif di dalam gambar PNG tanpa perubahan visual yang berarti, atau sekadar mengenkripsi file secara mandiri.

## 🛡️ Fitur & Keamanan

### 1. Enkripsi (AES-256-GCM)
- **Authenticated Encryption**: Menggunakan mode GCM untuk memastikan integritas data (data tidak bisa dimodifikasi tanpa merusak enkripsi).
- **Key Derivation (PBKDF2)**: Password diproses menggunakan PBKDF2-HMAC-SHA256 dengan 200.000 iterasi dan salt unik per file, membuatnya sangat tahan terhadap serangan *brute-force*.
- **Format V2**: Setiap file memiliki *nonce* dan *salt* acak, sehingga mengenkripsi data yang sama dengan password yang sama akan menghasilkan output yang berbeda.

### 2. Steganografi (Adaptive LSB)
- **Content-Adaptive**: Bit tidak disisipkan secara buta. Alat ini menganalisis tekstur gambar dan memprioritaskan penyisipan pada area yang "berisik" atau bertekstur tinggi (tepi/objek detil) agar sulit dideteksi mata manusia.
- **Keyed Permutation**: Urutan channel warna (R, G, B) yang digunakan untuk menyimpan bit diacak berdasarkan password Anda.
- **Obfuscated Metadata**: Ukuran data rahasia disamarkan dengan *bitmasking* berbasis hash password.

## 🚀 Instalasi

Pastikan Anda memiliki **Python 3.10+**.

1. Klon atau unduh repositori ini.
2. Instal dependensi:
```bash
pip install -r requirements.txt
```

Extract payload dari gambar:

- Print ke terminal (kalau payload text/UTF-8):

```bash
python dexenc.py extract -i out.png -key "password"
```

- Simpan ke file (untuk payload binary):

```bash
python dexenc.py extract -i out.png -key "password" --out-payload extracted.bin
```

### Encrypt/Decrypt Payload Saja (tanpa stego)

Encrypt file payload jadi file terenkripsi:

```bash
python dexenc.py encrypt -p payload.bin -o payload.dexenc -key "password"
```

Decrypt file terenkripsi jadi payload lagi:

```bash
python dexenc.py decrypt -p payload.dexenc --out-payload payload.bin -key "password"
```

### Contoh (Windows & Linux)

Windows (PowerShell):

```powershell
python -m pip install -r requirements.txt
python dexenc.py hide -i .\\cover.png -p .\\payload.bin -o .\\out.png -key "passphrase panjang"
python dexenc.py extract -i .\\out.png -key "passphrase panjang" --out-payload .\\extracted.bin
python dexenc.py encrypt -p .\\payload.bin -o .\\payload.dexenc -key "passphrase panjang"
python dexenc.py decrypt -p .\\payload.dexenc --out-payload .\\payload.bin -key "passphrase panjang"
```

Linux/macOS (bash):

```bash
python3 -m pip install -r requirements.txt
python3 dexenc.py hide -i ./cover.png -p ./payload.bin -o ./out.png -key "passphrase panjang"
python3 dexenc.py extract -i ./out.png -key "passphrase panjang" --out-payload ./extracted.bin
python3 dexenc.py encrypt -p ./payload.bin -o ./payload.dexenc -key "passphrase panjang"
python3 dexenc.py decrypt -p ./payload.dexenc --out-payload ./payload.bin -key "passphrase panjang"
```

### Default Folder `input/` dan `output/`

Kalau kamu pakai nama file tanpa path (mis. `payload.bin`), tool akan:

- cari input dari `input/payload.bin`
- simpan output ke `output/...`
- untuk mode `extract`/`decrypt`, kalau file tidak ketemu di `input/`, tool juga akan coba cari di `output/`.

Contoh:

```bash
python dexenc.py hide -i cover.png -p payload.bin -o out.png -key "password"
```

Itu ekuivalen dengan:

```bash
python dexenc.py hide -i input/cover.png -p input/payload.bin -o output/out.png -key "password"
```

### Kapasitas Payload (penting)

Metode LSB menyimpan 1 bit per channel RGB (3 bit per pixel).

- Kapasitas bit: `width * height * 3`
- Versi terbaru menyebar bit payload secara acak (scatter) berbasis password + salt, dan panjang payload di-obfuscate. Ini membuat ekstraksi tanpa password jauh lebih sulit (meski tetap tidak membuat LSB “tidak terdeteksi”).
- Versi terbaru juga memakai **content-adaptive embedding**: bit disisipkan terutama di area yang lebih “bertekstur/berisik”. Kamu bisa atur ambang tekstur via env `DEXENC_EDGE_THRESHOLD` (0–255). Nilai lebih kecil = kapasitas lebih besar tapi lebih mudah terdeteksi; nilai lebih besar = lebih “stealth” tapi kapasitas turun.
- Payload yang disimpan adalah **hasil enkripsi**, jadi ukurannya sedikit lebih besar dari file asli.

Perkiraan kapasitas byte maksimum:

```
max_bytes ≈ (width * height * 3 - 32) / 8
```

Kalau payload kebesaran, tool akan error: “Payload terlalu besar untuk gambar”.

### Troubleshooting

- `Gagal dekripsi. Password salah atau data rusak.`
  - Password salah, atau gambar sudah berubah (mis. jadi JPG / di-resize).
- `Data length marker invalid...`
  - Gambar tidak berisi payload DEX-ENC, atau payload rusak.
- File output folder belum ada
  - Sekarang akan auto dibuat (mis. `out/hasil.png`).

### Seberapa Aman?

Enkripsi:

- AES-256-GCM adalah skema enkripsi+autentikasi yang kuat **kalau password kuat**.
- Versi terbaru `DexCrypter` memakai PBKDF2-HMAC-SHA256 (dengan salt per file + iterasi) untuk memperlambat brute-force password.

Steganografi (LSB):

- LSB **mudah dideteksi** oleh analisis steganalysis jika lawan memang mencari payload. Jadi ini lebih cocok untuk “menyembunyikan dari penglihatan biasa”, bukan untuk adversary yang kuat.
- Jangan anggap stego sebagai pengganti enkripsi. Stego hanya “kamuflase”, keamanan utama tetap dari password + AES-GCM.

Rekomendasi keamanan praktis:

- Gunakan passphrase panjang (mis. 4–6 kata acak) dan jangan pakai password umum.
- Jangan re-use gambar cover yang sama berkali-kali untuk payload berbeda.
- Simpan output sebagai PNG, jangan upload ke platform yang auto-compress (biasanya merusak LSB).
