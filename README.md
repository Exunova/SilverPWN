# SilverPWN

SilverPWN is a local-first Python  helper for CTF PWN / binary exploitation challenges.

It performs reconnaissance first, tries deterministic exploit strategies locally, extracts flags from program output or safe local flag-hunting paths, and replays a validated local payload against a remote target when one is provided.

## Features

- ELF reconnaissance: architecture, NX, PIE, canary, RELRO, stripped status, libc, symbols, GOT, PLT, interesting strings, and input sinks.
- Local-first exploitation workflow.
- Keeps crash dumps tidy by moving `core` / `core.*` files into a per-challenge `core/` folder.
- Works with ELF binaries, C sources, or challenge folders.
- Windows compatibility through automatic WSL re-exec when available.
- Strategy modules for ret2win, stack overflow, scanf/strcpy-style overflow, bounded padding/admin flips, variable overwrite, OOB write, format string leak/write, GOT overwrite, canary-leak overflow, PIE leak ret2win, ROP print-file, ROP Emporium-style split/callme/write4/badchars/fluff/pivot/ret2csu, i386 shellcode ORW/start patterns, menu handoff stack shellcode, duplicate `LD_PRELOAD` env bypasses, menu file-read traversal, tcache poisoning with safe-linking, UAF, heap overflow function pointer, PicoCTF classics, and local flag hunting.
- Ret2win discovery is symbol- and source-assisted: SilverPWN looks beyond a literal `win` symbol for flag-printing/opening functions such as `print_flag`, `read_flag`, `show_flag`, `get_flag`, hidden admin/secret functions, and source functions whose bodies touch flag-like file paths or `system`. For binaries that report canary support globally, SilverPWN can still try ret2win when the vulnerable input function itself disassembles as unprotected.
- Regression runner for the generated 200-case corpus and PicoCTF artifact pack.

## Install

Linux or WSL is recommended.

```bash
python3 -m pip install -r requirements.txt
sudo apt-get install -y gcc gdb binutils
```

Optional but useful:

```bash
python3 -m pip install angr
```

On Windows, run with normal Python from this folder. SilverPWN will re-execute itself in WSL if `wsl.exe` is available.

## Usage

```bash
python3 SilverPWN.py ./chall
python3 SilverPWN.py ./source.c
python3 SilverPWN.py ./challenge-folder
python3 SilverPWN.py ./chall host:port
python3 SilverPWN.py ./chall "nc host port" --flag FlagFormat
python3 SilverPWN.py ./chall nc host port --flag FlagFormat
python3 SilverPWN.py ./chall --libc ./libc.so.6
```

JSON output:

```bash
python3 SilverPWN.py ./chall --json
```

Strict regression mode without local `flag.txt` fallback:

```bash
python3 SilverPWN.py ./chall --no-file-hunter
```