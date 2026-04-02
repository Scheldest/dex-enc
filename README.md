# DEX-ENC: Secure Image Steganography & Encryption

**DEX-ENC** adalah alat baris perintah (CLI) canggih yang menggabungkan enkripsi standar militer **AES-256-GCM** dengan teknik steganografi **Content-Adaptive LSB**. Alat ini memungkinkan Anda menyembunyikan data sensitif di dalam gambar PNG tanpa perubahan visual yang berarti, atau sekadar mengenkripsi file secara mandiri.

## Fitur & Keamanan

### 1. Enkripsi (AES-256-GCM)
- **Authenticated Encryption**: Menggunakan mode GCM untuk memastikan integritas data (data tidak bisa dimodifikasi tanpa merusak enkripsi).
- **Key Derivation (PBKDF2)**: Password diproses menggunakan PBKDF2-HMAC-SHA256 dengan 200.000 iterasi dan salt unik per file, membuatnya sangat tahan terhadap serangan *brute-force*.
- **Format V2**: Setiap file memiliki *nonce* dan *salt* acak, sehingga mengenkripsi data yang sama dengan password yang sama akan menghasilkan output yang berbeda.

### 2. Steganografi (Adaptive LSB)
- **Content-Adaptive**: Bit tidak disisipkan secara buta. Alat ini menganalisis tekstur gambar dan memprioritaskan penyisipan pada area yang "berisik" atau bertekstur tinggi (tepi/objek detil) agar sulit dideteksi mata manusia.
- **Keyed Permutation**: Urutan channel warna (R, G, B) yang digunakan untuk menyimpan bit diacak berdasarkan password Anda.
- **Obfuscated Metadata**: Ukuran data rahasia disamarkan dengan *bitmasking* berbasis hash password.

## Instalasi

Pastikan Anda memiliki **Python 3.10+**.

1. Klon atau unduh repositori ini.
2. Instal dependensi:
```bash
pip install .
```

Extract payload dari gambar:

- Print ke terminal (kalau payload text/UTF-8):

```bash
dexenc extract -i out.png -key "password"
```

- Simpan ke file (untuk payload binary):

```bash
dexenc.py extract -i out.png -key "password" --out-payload extracted.bin
```

### Encrypt/Decrypt Payload Saja (tanpa stego)

Encrypt file payload jadi file terenkripsi:

```bash
dexenc.py encrypt -p payload.bin -o payload.dexenc -key "password"
```

Decrypt file terenkripsi jadi payload lagi:

```bash
dexenc.py decrypt -p payload.dexenc --out-payload payload.bin -key "password"
```

### Contoh (Windows & Linux)

Windows (PowerShell):

```powershell
pip install .
dexenc hide -i .\\cover.png -p .\\payload.bin -o .\\out.png -key "passphrase panjang"
dexenc extract -i .\\out.png -key "passphrase panjang" --out-payload .\\extracted.bin
dexenc encrypt -p .\\payload.bin -o .\\payload.dexenc -key "passphrase panjang"
dexenc decrypt -p .\\payload.dexenc --out-payload .\\payload.bin -key "passphrase panjang"
```

## Konfigurasi Argumen

| Argumen | Deskripsi |
| :--- | :--- |
| `-i, --input` | File sumber (gambar atau payload). |
| `-p, --payload` | File rahasia yang ingin disisipkan (hanya untuk `hide`). |
| `-o, --output` | Nama file hasil. Jika kosong saat extract, akan print ke terminal. |
| `-key, --password` | Password untuk proses enkripsi/dekripsi. |
| `--quiet` | Mode senyap (hanya menampilkan pesan error). |

### Kapasitas Payload (penting)

Metode LSB menyimpan 1 bit per channel RGB (3 bit per pixel).
- Tool ini menggunakan **content-adaptive embedding**: bit hanya disisipkan di area gambar yang memiliki tekstur/detil tinggi agar tidak kasat mata.
- Anda bisa mengatur sensitivitas area melalui env variable `DEXENC_EDGE_THRESHOLD` (Default: 24).
- Gunakan format **PNG** untuk hasil terbaik. Format JPG akan merusak data karena kompresi lossy.

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
