#!/usr/bin/env python3
"""Patch frida-kmod.c: mark __nocfi the 4 functions that indirectly call
kprobe-resolved unexported symbols, otherwise CFI (CONFIG_CFI_CLANG on GKI
5.15) panics with "CFI failure (target: kallsyms_lookup_name+0x0/0xec)". """
import sys

path = sys.argv[1]
with open(path, "r") as f:
    s = f.read()

subs = [
    ("static void\nfrida_resolve_kallsyms (void)",
     "static void __nocfi\nfrida_resolve_kallsyms (void)"),
    ("int\nfrida_kmod_protect (u64 address",
     "int __nocfi\nfrida_kmod_protect (u64 address"),
    ("u64\nfrida_kmod_find_symbol (const char * name)",
     "u64 __nocfi\nfrida_kmod_find_symbol (const char * name)"),
    ("int\nfrida_kmod_enumerate_symbols (FridaFoundSymbolFunc func",
     "int __nocfi\nfrida_kmod_enumerate_symbols (FridaFoundSymbolFunc func"),
]

for old, new in subs:
    if old not in s:
        print(f"WARNING: pattern not found: {old!r}")
    s = s.replace(old, new)

with open(path, "w") as f:
    f.write(s)

print("patched:", path)
