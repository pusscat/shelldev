# tools — regenerating the Metasploit catalog

`app/msf_catalog.py` is **vendored**: the shellcode bytes are generated once,
offline, and checked in, so the running app needs no Metasploit dependency.
These two scripts regenerate it. You only need them when refreshing the set
(e.g. after a Metasploit update or to change the defaults).

## What gets generated
- Every *single* (stageless) native x86/x64/arm64 payload across all OSes
  Metasploit supports (staged/meterpreter are skipped — they need a handler).
- Every x86/x64 encoder's real decoder stub (`shikata_ga_nai` excluded;
  alphanumeric encoders use `BufferRegister` ECX/RCX).
- The x86 egghunter stubs (Linux and Windows), tag `w00t`.

Network payloads bake in a dummy `LHOST 127.0.0.1` / `LPORT 4444`, exec payloads
a dummy command, and egghunters the tag `w00t`; those immediates are flagged
inline in the assembly the app shows.

## Steps
Run from the repo root. The first step needs the Metasploit Framework installed
and must run under **its** Ruby (it loads the framework in-process — far faster
than one `msfvenom` per payload):

```sh
# 1. generate the bytes (JSON). Override MSF_FRAMEWORK if installed elsewhere.
/opt/metasploit-framework/embedded/bin/ruby tools/gen_msf_catalog.rb /tmp/msf_entries.json

# 2. emit the vendored Python module from that JSON.
python3 tools/emit_msf_catalog.py /tmp/msf_entries.json app/msf_catalog.py
```

Step 2 has no Metasploit dependency. The disassembly and the "faithful assembly"
construction (any instruction that doesn't re-encode to its own bytes becomes a
`.byte` directive, so inline data can't cause cascading misalignment) run in the
app at load time against its own Keystone/Capstone engine — so a rebuild is all
that's needed to pick up a new `msf_catalog.py`.
