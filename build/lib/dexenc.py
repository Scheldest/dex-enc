import sys
import os
import argparse
import base64
from pathlib import Path
from core.crypter import DexCrypter
from core.stego import DexStego
from core.ui import clear_screen, print_banner, print_status

def _has_flag(argv: list[str], flag: str) -> bool:
    return flag in argv

def _auto_banner_from_argv(argv: list[str]) -> None:
    """Menangani tampilan banner berdasarkan argumen atau env."""
    if _has_flag(argv, "--no-color"): os.environ["DEXENC_NO_COLOR"] = "1"
    if _has_flag(argv, "--quiet") or _has_flag(argv, "--no-banner"): return
    
    if not (_has_flag(argv, "--no-clear") or os.environ.get("DEXENC_NO_CLEAR") == "1"):
        clear_screen()
    print_banner()

def main():
    _auto_banner_from_argv(sys.argv[1:])

    parser = argparse.ArgumentParser(description="DEX-ENC: Advanced Image Steganography with AES-256")
    parser.add_argument("action", choices=["hide", "extract", "encrypt", "decrypt"], help="Aksi yang dilakukan")
    
    # Input/Output Args
    parser.add_argument("-i", "--input", required=True, help="File input utama (gambar atau payload)")
    parser.add_argument("-p", "--payload", help="File rahasia yang akan disisipkan (hanya untuk mode 'hide')")
    parser.add_argument("-o", "--output", help="Path file output hasil proses. Jika kosong pada extract/decrypt, akan print ke terminal.")
    parser.add_argument("-key", "--password", required=True, help="Password enkripsi")
    
    # UI/UX Args
    parser.add_argument("--quiet", action="store_true", help="Minimalkan output terminal")
    parser.add_argument("--no-banner", action="store_true", help="Jangan tampilkan banner ASCII")
    parser.add_argument("--no-clear", action="store_true", help="Jangan clear terminal otomatis (atau set DEXENC_NO_CLEAR=1)")
    parser.add_argument("--no-color", action="store_true", help="Matikan warna ANSI (atau set NO_COLOR / DEXENC_NO_COLOR=1)")

    args = parser.parse_args()
    
    try:
        crypter = DexCrypter(args.password)
        stego = DexStego()

        input_path = Path(args.input)
        if not input_path.exists():
            return print_status("error", f"File input tidak ditemukan: {args.input}")

        if args.action == "hide":
            if not args.payload or not args.output:
                return print_status("error", "Mode hide butuh: -i (gambar), -p (file rahasia), -o (hasil)")
            
            payload_path = Path(args.payload)
            if not payload_path.exists():
                return print_status("error", f"Payload tidak ditemukan: {args.payload}")

            if not args.quiet: print_status("info", f"Menyisipkan {payload_path.name} ke {input_path.name}...")
            encrypted_data = crypter.encrypt(payload_path.read_bytes())
            stego.hide_data(str(input_path), encrypted_data, args.output, password=args.password)
            if not args.quiet: print_status("success", f"Selesai! Gambar disimpan di: {args.output}")

        elif args.action == "extract":
            if not args.quiet: print_status("info", "Mengekstrak data dari gambar...")
            raw_encrypted = stego.extract_data(str(input_path), password=args.password)
            decrypted = crypter.decrypt(raw_encrypted)
            
            if decrypted is None:
                return print_status("error", "Gagal dekripsi. Password salah atau gambar rusak.")

            if args.output:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(decrypted)
                if not args.quiet: print_status("success", f"Data disimpan ke: {args.output}")
            else:
                if not args.quiet: print_status("success", "Isi data:\n")
                print(decrypted.decode("utf-8", errors="replace"))

        elif args.action == "encrypt":
            out_path = Path(args.output or (input_path.stem + ".dexenc"))
            if out_path.suffix != ".dexenc": out_path = out_path.with_suffix(".dexenc")

            if not args.quiet: print_status("info", f"Mengenkripsi {input_path.name}...")
            encrypted = crypter.encrypt(input_path.read_bytes())
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(encrypted)
            if not args.quiet: print_status("success", f"File terenkripsi: {out_path}")

        elif args.action == "decrypt":
            if not args.quiet: print_status("info", f"Mendekripsi {input_path.name}...")
            decrypted = crypter.decrypt(input_path.read_bytes())
            
            if decrypted is None:
                return print_status("error", "Gagal dekripsi. Password salah.")

            if args.output:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(decrypted)
                if not args.quiet: print_status("success", f"File didekripsi ke: {args.output}")
            else:
                if not args.quiet: print_status("success", "Isi file:\n")
                print(decrypted.decode("utf-8", errors="replace"))
            
    except Exception as e:
        print_status("error", f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    main()
