# Laporan Proyek Kriptografi Hibrida

## Identitas

- Nama: al ghazali
- NIM: 231111051
- Mata Kuliah: Kriptografi Hibrida

## Deskripsi Proyek

Proyek ini mengimplementasikan sistem keamanan hibrida menggunakan beberapa algoritma kriptografi sebagai berikut:

- AES-128 CBC untuk enkripsi data simetris
- RSA untuk pengamanan kunci AES
- Schnorr untuk tanda tangan digital
- SHA256 untuk hashing pesan
- Diffie-Hellman untuk pertukaran kunci
- Steganografi LSB pada BMP untuk menyembunyikan pesan

## Struktur Berkas

- `hybrid_crypto.py`: Implementasi utama algoritma kriptografi dan demo interaktif.
- `README.md`: Panduan penggunaan dan informasi proyek.
- `LAPORAN_GITHUB.md`: Laporan proyek ini dalam format GitHub.

## Tujuan

Tujuan proyek ini adalah membuat contoh sistem kriptografi hibrida yang menggabungkan:

1. Enkripsi simetris dan asimetris
2. Hashing dan tanda tangan digital
3. Mekanisme pertukaran kunci
4. Teknik steganografi sederhana

## Fitur Utama

1. Enkripsi AES-128 CBC untuk menjaga kerahasiaan pesan.
2. RSA untuk mengenkripsi kunci AES sehingga dapat ditransmisikan dengan aman.
3. Schnorr signature untuk memastikan keaslian dan integritas pesan.
4. SHA256 untuk membuat ringkasan pesan.
5. Diffie-Hellman untuk menghasilkan shared secret secara aman.
6. Steganografi LSB untuk menyembunyikan pesan teks dalam file BMP.

## Cara Menjalankan

1. Masuk ke folder proyek:

```bash
cd "c:\Users\User\Downloads\Program Kriptografi Hibrida"
```

2. Jalankan demo Python:

```bash
py hybrid_crypto.py
```

3. Untuk menyembunyikan pesan pada file BMP:

```python
from hybrid_crypto import embed_text_in_bmp
embed_text_in_bmp("input.bmp", "output_hidden.bmp", "al ghazali 231111051")
```

4. Untuk mengambil pesan tersembunyi:

```python
from hybrid_crypto import extract_text_from_bmp
text = extract_text_from_bmp("output_hidden.bmp")
print(text)
```

## Hasil Output Demo

Demo sekarang menampilkan:

- Pesan asli dan hash SHA256
- AES key dan ciphertext preview
- Enkripsi kunci AES menggunakan RSA
- Verifikasi tanda tangan Schnorr
- Pertukaran kunci Diffie-Hellman dan hash shared secret
- Panduan penggunaan steganografi

## Catatan Teknis

- AES dekripsi belum diimplementasikan sepenuhnya dalam berkas ini.
- RSA dan Schnorr menggunakan implementasi matematika sederhana untuk tujuan pembelajaran.
- Steganografi LSB hanya mendukung file BMP tanpa kompresi.

## Saran Pengembangan Selanjutnya

- Lengkapi dekripsi AES CBC agar bisa memulihkan pesan asli.
- Tambahkan validasi format BMP dan ukuran pesan.
- Gunakan bilangan prima yang lebih besar untuk keamanan RSA dan Schnorr.
- Tambahkan dokumentasi penggunaan GitHub Actions atau CI jika ingin membuat repositori publik.

---

> Laporan ini disiapkan untuk dokumentasi proyek kriptografi hibrida dengan format yang siap dipublikasikan di GitHub.
