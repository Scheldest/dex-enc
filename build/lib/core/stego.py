from PIL import Image
from pathlib import Path
import os
import hashlib
from typing import Optional, Union
from collections.abc import Generator


class DexStego:
    _MAGIC_V2 = b"DSG2"
    _SALT_LEN_V2 = 16
    _MAGIC_V3 = b"DSG3"
    _SALT_LEN_V3 = 16
    _SALT_LEN = 16
    _HEADER_V3_LEN_BYTES = 4 + 16 + 2  # magic + salt + (threshold, flags)
    _FLAGS_V3 = 0x02  # bit1: channel permutation
    _DEFAULT_EDGE_THRESHOLD = 24

    _CHANNEL_PERMS: tuple[tuple[int, int, int], ...] = (
        (0, 1, 2),
        (0, 2, 1),
        (1, 0, 2),
        (1, 2, 0),
        (2, 0, 1),
        (2, 1, 0),
    )

    @staticmethod
    def bytes_to_bits(data):
        return ''.join(format(b, '08b') for b in data)

    @staticmethod
    def bits_to_bytes(bit_str):
        byte_arr = bytearray()
        for i in range(0, len(bit_str), 8):
            byte_arr.append(int(bit_str[i:i+8], 2))
        return bytes(byte_arr)

    @staticmethod
    def _password_bytes(password: Union[str, bytes]) -> bytes:
        if isinstance(password, bytes):
            return password
        return str(password).encode("utf-8")

    @classmethod
    def _derive_key_v2(cls, password: Union[str, bytes], salt: bytes) -> bytes:
        # Deterministic key for stego scatter; encryption is handled separately in DexCrypter.
        pw = cls._password_bytes(password)
        return hashlib.sha256(b"DEXSTEGO2" + pw + b"\x00" + salt).digest()

    @classmethod
    def _derive_key_v3(cls, password: Union[str, bytes], salt: bytes) -> bytes:
        pw = cls._password_bytes(password)
        return hashlib.sha256(b"DEXSTEGO3" + pw + b"\x00" + salt).digest()

    @staticmethod
    def _bitpos_to_xyc(bit_pos: int, width: int) -> tuple[int, int, int]:
        pixel_index = bit_pos // 3
        channel = bit_pos % 3  # 0=r 1=g 2=b
        y = pixel_index // width
        x = pixel_index % width
        return x, y, channel

    @staticmethod
    def _base_rgb(pixel: tuple[int, int, int]) -> tuple[int, int, int]:
        # Clear LSB so scoring is stable even after embedding.
        r, g, b = pixel
        return (r & ~1, g & ~1, b & ~1)

    @classmethod
    def _texture_score_byte(cls, pixels, x: int, y: int, width: int, height: int) -> int:
        r0, g0, b0 = cls._base_rgb(pixels[x, y])

        if x + 1 < width:
            r1, g1, b1 = cls._base_rgb(pixels[x + 1, y])
        else:
            r1, g1, b1 = cls._base_rgb(pixels[x - 1, y]) if x > 0 else (r0, g0, b0)

        if y + 1 < height:
            r2, g2, b2 = cls._base_rgb(pixels[x, y + 1])
        else:
            r2, g2, b2 = cls._base_rgb(pixels[x, y - 1]) if y > 0 else (r0, g0, b0)

        score = (
            abs(r0 - r1) + abs(g0 - g1) + abs(b0 - b1) + abs(r0 - r2) + abs(g0 - g2) + abs(b0 - b2)
        )
        return min(score // 6, 255)

    @classmethod
    def _pixel_perm(cls, key: bytes, pixel_index: int) -> tuple[int, int, int]:
        digest = hashlib.sha256(b"ORD3" + key + pixel_index.to_bytes(4, "big")).digest()
        return cls._CHANNEL_PERMS[digest[0] % len(cls._CHANNEL_PERMS)]

    @staticmethod
    def _pm_choice_byte(key: bytes, bit_index: int) -> int:
        return hashlib.sha256(b"PM3" + key + bit_index.to_bytes(4, "big")).digest()[0]

    @classmethod
    def _resolve_edge_threshold(cls) -> int:
        raw = os.environ.get("DEXENC_EDGE_THRESHOLD", "").strip()
        if not raw:
            return cls._DEFAULT_EDGE_THRESHOLD
        try:
            v = int(raw)
        except ValueError:
            return cls._DEFAULT_EDGE_THRESHOLD
        return max(0, min(255, v))

    def _get_bit_locations(self, pixels, width, height, threshold, key, flags, start_pos) -> Generator[tuple[int, int, int], None, None]:
        """Generator untuk mencari lokasi bit yang valid (adaptive + permuted)."""
        for y in range(height):
            for x in range(width):
                if self._texture_score_byte(pixels, x, y, width, height) < threshold:
                    continue
                pixel_index = (y * width) + x
                perm = self._pixel_perm(key, pixel_index) if (flags & 0x02) else (0, 1, 2)
                for c in perm:
                    bit_pos = (pixel_index * 3) + c
                    if bit_pos >= start_pos:
                        yield (x, y, c)

    def hide_data(self, img_path, data_bytes, output_path, password: Optional[Union[str, bytes]] = None):
        img = Image.open(img_path).convert('RGB')
        pixels = img.load()
        
        width, height = img.size
        capacity_bits = width * height * 3

        # V3 (recommended): content-adaptive (edge/texture) + keyed channel permutation + LSB matching.
        if password:
            salt = os.urandom(self._SALT_LEN_V3)
            threshold = self._resolve_edge_threshold()
            header = self._MAGIC_V3 + salt + bytes([threshold, self._FLAGS_V3])
            header_bits = self.bytes_to_bits(header)
            header_end_bitpos = len(header_bits)

            key = self._derive_key_v3(password, salt)
            # Obfuscate length (u32be) so it can't be read without password.
            length_mask = int.from_bytes(hashlib.sha256(b"LEN3" + key).digest()[:4], "big")
            length_u32 = len(data_bytes) & 0xFFFFFFFF
            length_obf = (length_u32 ^ length_mask) & 0xFFFFFFFF
            len_bits = format(length_obf, "032b")

            payload_bits = len_bits + self.bytes_to_bits(data_bytes)
            total_bits_needed = len(header_bits) + len(payload_bits)
            if total_bits_needed > capacity_bits:
                raise ValueError(
                    f"Payload terlalu besar untuk gambar. Butuh {total_bits_needed} bit, kapasitas {capacity_bits} bit."
                )

            # 1) Write header sequentially.
            for i, bit in enumerate(header_bits):
                x, y, c = self._bitpos_to_xyc(i, width)
                channels = list(pixels[x, y])
                channels[c] = (channels[c] & ~1) | int(bit)
                pixels[x, y] = tuple(channels)
            available_bits = 0
            for y in range(height):
                for x in range(width):
                    if self._texture_score_byte(pixels, x, y, width, height) < threshold:
                        continue
                    pixel_index = (y * width) + x
                    for c in (0, 1, 2):
                        bit_pos = (pixel_index * 3) + c
                        if bit_pos >= header_end_bitpos:
                            available_bits += 1
            if len(payload_bits) > available_bits:
                raise ValueError(
                    "Area bertekstur tidak cukup untuk payload. "
                    f"Butuh {len(payload_bits)} bit, tersedia {available_bits} bit. "
                    "Coba pakai gambar yang lebih noisy/bertekstur, perbesar resolusi, atau turunkan threshold "
                    "(set env DEXENC_EDGE_THRESHOLD lebih kecil)."
                )

            # 2) Embed payload bits (scan order on textured pixels)
            bit_gen = self._get_bit_locations(pixels, width, height, threshold, key, self._FLAGS_V3, header_end_bitpos)
            bit_index = 0
            for x, y, c in bit_gen:
                if bit_index >= len(payload_bits): break
                channels = list(pixels[x, y])
                channels[c] = (channels[c] & ~1) | int(payload_bits[bit_index])
                pixels[x, y] = tuple(channels)
                bit_index += 1

            if bit_index < len(payload_bits):
                raise ValueError("Kapasitas gambar tidak cukup (area tekstur terlalu sedikit).")
        else:
            # Legacy: sequential length marker (32 bit) + payload bits.
            bit_data = format(len(data_bytes), '32b').replace(' ', '0') + self.bytes_to_bits(data_bytes)
            if len(bit_data) > capacity_bits:
                raise ValueError(
                    f"Payload terlalu besar untuk gambar. Butuh {len(bit_data)} bit, kapasitas {capacity_bits} bit."
                )

            idx = 0
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    channels = [r, g, b]
                    for i in range(3):
                        if idx < len(bit_data):
                            channels[i] = (channels[i] & ~1) | int(bit_data[idx])
                            idx += 1
                    pixels[x, y] = tuple(channels)
                    if idx >= len(bit_data): break
                if idx >= len(bit_data): break
        
        out_path = Path(output_path)
        if out_path.parent and not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        img.save(output_path, "PNG")

    def extract_data(self, img_path, password: Optional[Union[str, bytes]] = None):
        img = Image.open(img_path).convert('RGB')
        pixels = img.load()
        width, height = img.size
        capacity_bits = width * height * 3

        # Try V3/V2 first if password is provided: read sequential header then parse.
        if password:
            header_len_bits = self._HEADER_V3_LEN_BYTES * 8
            if capacity_bits >= header_len_bits:
                header_bits = []
                for i in range(header_len_bits):
                    x, y, c = self._bitpos_to_xyc(i, width)
                    chan = pixels[x, y][c]
                    header_bits.append("1" if (chan & 1) else "0")
                header = self.bits_to_bytes("".join(header_bits))
                magic = header[:4]
                
                if magic == self._MAGIC_V3 and len(header) >= self._HEADER_V3_LEN_BYTES:
                    salt = header[4:20]
                    threshold = header[20]
                    flags = header[21]
                    key = self._derive_key_v3(password, salt)
                    length_mask = int.from_bytes(hashlib.sha256(b"LEN3" + key).digest()[:4], "big")

                    bit_gen = self._get_bit_locations(pixels, width, height, threshold, key, flags, header_len_bits)
                    len_bits = []
                    data_bits = []
                    data_len: Optional[int] = None

                    for x, y, c in bit_gen:
                        bit = "1" if (pixels[x, y][c] & 1) else "0"
                        if data_len is None:
                            len_bits.append(bit)
                            if len(len_bits) == 32:
                                data_len = (int("".join(len_bits), 2) ^ length_mask) & 0xFFFFFFFF
                        else:
                            data_bits.append(bit)
                            if len(data_bits) == data_len * 8:
                                return self.bits_to_bytes("".join(data_bits))
                                
                    raise ValueError("Data tidak ditemukan atau threshold salah.")

                # Legacy keyed-scatter V2 (DSG2)
                header_len_bits_v2 = (4 + self._SALT_LEN) * 8
                if capacity_bits >= header_len_bits_v2:
                    header_bits_v2 = []
                    for i in range(header_len_bits_v2):
                        x, y, c = self._bitpos_to_xyc(i, width)
                        chan = pixels[x, y][c]
                        header_bits_v2.append("1" if (chan & 1) else "0")
                    header_v2 = self.bits_to_bytes("".join(header_bits_v2))
                    magic_v2 = header_v2[:4]
                    if magic_v2 == self._MAGIC_V2:
                        salt = header_v2[4:]
                        key = self._derive_key_v2(password, salt)
                        length_mask = int.from_bytes(hashlib.sha256(b"LEN" + key).digest()[:4], "big")

                        import random

                        shuffle_seed = int.from_bytes(hashlib.sha256(b"SHUF" + key).digest(), "big")
                        rng = random.Random(shuffle_seed)
                        positions = list(range(header_len_bits_v2, capacity_bits))
                        rng.shuffle(positions)

                        # Read obfuscated length first (32 bits)
                        if len(positions) < 32:
                            raise ValueError("Header stego invalid atau gambar tidak berisi payload yang valid.")
                        len_bits = []
                        for pos in positions[:32]:
                            x, y, c = self._bitpos_to_xyc(pos, width)
                            r, g, b = pixels[x, y]
                            chan = (r, g, b)[c]
                            chan = pixels[x, y][c]
                            len_bits.append("1" if (chan & 1) else "0")

                        length_obf = int("".join(len_bits), 2)
                        data_len = (length_obf ^ length_mask) & 0xFFFFFFFF

                        total_bits_needed = 32 + (data_len * 8)
                        if total_bits_needed > len(positions):
                            raise ValueError("Data length marker invalid atau gambar tidak berisi payload yang valid.")

                        data_bits = []
                        for pos in positions[32 : 32 + (data_len * 8)]:
                            x, y, c = self._bitpos_to_xyc(pos, width)
                            r, g, b = pixels[x, y]
                            chan = (r, g, b)[c]
                            data_bits.append("1" if (chan & 1) else "0")

                        return self.bits_to_bytes("".join(data_bits))
        
        all_bits = ""
        # Ambil 32 bit pertama untuk tahu panjang data
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                all_bits += f"{r&1}{g&1}{b&1}"
                if len(all_bits) >= 32: break
            if len(all_bits) >= 32: break
            
        data_len = int(all_bits[:32], 2)
        total_bits_needed = 32 + (data_len * 8)
        if total_bits_needed > capacity_bits:
            raise ValueError("Data length marker invalid atau gambar tidak berisi payload yang valid.")
        
        # Ambil sisa bit sesuai panjang data
        all_bits = ""
        idx = 0
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                for chan in [r, g, b]:
                    if idx < total_bits_needed:
                        all_bits += str(chan & 1)
                        idx += 1
                if idx >= total_bits_needed: break
            if idx >= total_bits_needed: break
            
        return self.bits_to_bytes(all_bits[32:])
