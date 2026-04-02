import os
import sys
from typing import Optional, TextIO


def _is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _enable_windows_vt_mode() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        return


def supports_color(stream: Optional[TextIO] = None) -> bool:
    s = stream or sys.stdout
    if not _is_tty(s):
        return False
    # Respect common opt-out conventions.
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("DEXENC_NO_COLOR", "").strip() == "1":
        return False
    _enable_windows_vt_mode()
    return True


def style(text: str, ansi: str, stream: Optional[TextIO] = None) -> str:
    if not supports_color(stream):
        return text
    return f"\x1b[{ansi}m{text}\x1b[0m"


def format_status(kind: str, message: str, stream: Optional[TextIO] = None) -> str:
    """
    kind: one of info, success, warn, error
    """
    k = kind.lower().strip()
    if k == "success":
        prefix = style("[+]", "92;1", stream)
    elif k in {"warn", "warning"}:
        prefix = style("[!]", "93;1", stream)
    elif k == "error":
        prefix = style("[-]", "91;1", stream)
    else:
        prefix = style("[*]", "96;1", stream)
    return f"{prefix} {message}"


def print_status(kind: str, message: str, stream: Optional[TextIO] = None) -> None:
    s = stream or sys.stdout
    s.write(format_status(kind, message, stream=s) + "\n")
    s.flush()


def _safe_text(text: str, stream: TextIO) -> str:
    enc = getattr(stream, "encoding", None)
    if not enc:
        return text
    try:
        "•".encode(enc)
    except Exception:
        return text.replace("•", "*")
    return text


def clear_screen(stream: Optional[TextIO] = None) -> None:
    s = stream or sys.stdout
    if not _is_tty(s):
        return
    _enable_windows_vt_mode()
    s.write("\x1b[2J\x1b[H")
    s.flush()


def print_banner(stream: Optional[TextIO] = None) -> None:
    s = stream or sys.stdout
    _enable_windows_vt_mode()
    art = r"""
@@@@@@@   @@@@@@@@  @@@  @@@  @@@@@@@@  @@@  @@@   @@@@@@@ 
@@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@ @@@  @@@@@@@@ 
@@!  @@@  @@!       @@!  !@@  @@!       @@!@!@@@  !@@      
!@!  @!@  !@!       !@!  @!!  !@!       !@!!@!@!  !@!      
@!@  !@!  @!!!:!     !@@!@!   @!!!:!    @!@ !!@!  !@!      
!@!  !!!  !!!!!:      @!!!    !!!!!:    !@!  !!!  !!!      
!!:  !!!  !!:        !: :!!   !!:       !!:  !!!  :!!      
:!:  !:!  :!:       :!:  !:!  :!:       :!:  !:!  :!:      
:::: ::   :: ::::   ::   :::  :: ::::   ::   ::   ::: ::: 
:: : :    : :: ::    :   ::   : :: ::   ::    :    :: :: : 
"""
    if supports_color(s):
        s.write(style(art.rstrip("\n"), "94;1", stream=s) + "\n\n")
    else:
        s.write(art.rstrip("\n") + "\n\n")

    tagline = _safe_text("DEX-ENC - steganography + AES-256 (GCM)", s)
    if supports_color(s):
        s.write(style(tagline, "90", stream=s) + "\n\n")
    else:
        s.write(tagline + "\n\n")
    s.flush()
