# stor — HPE Build-It / Break-It entry

`stor` is a 32-bit C command-line "encrypted file store". This repository is the
contest submission: `build/` holds the source + Makefile that produce `./stor`,
and `break/` is reserved for the Break-It phase.

> **Status: functional + encrypted.** The full CLI contract runs over a
> libsodium-encrypted `enc.db`. All crypto lives in `db.c`; callers pass the
> password string and get plaintext back, and the derived key never leaves the
> module. See **Security model** below.

## Layout

```
build/
  Makefile          # mandated flags; `all` = build + execstack
  malloc-2.7.2.c    # Doug Lea dlmalloc 2.7.2 (public domain), the program allocator
  stor.c            # main(): parse -> load db -> dispatch -> save; defines win()
  args.c/.h         # argv tokenizer (last-wins) + per-command validation
  db.c/.h           # enc.db load/save + in-memory model + ALL libsodium crypto
  cmd.c/.h          # register/create/write/read business logic
  io.c/.h           # input (-i / inline text / stdin), output (-o / stdout)
break/              # Break-It phase (placeholder)
Dockerfile          # Ubuntu 18.04 + 32-bit toolchain + execstack (build/grade parity)
```

## Build

The mandated build line (in `build/Makefile`) is:

```
gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c args.c db.c cmd.c io.c malloc-2.7.2.c -lsodium
execstack --set-execstack stor
```

The mandated flags are unchanged; `-lsodium` is appended as a link library
(`libsodium-dev` + the i386 runtime must be installed — the Dockerfile stages both).

`all` (default) chains both; `build` and `post` are also callable by name.

```sh
cd build && make          # -> ./stor, with the executable-stack flag set
execstack -q stor         # expect: X stor
```

This needs a 32-bit toolchain (`gcc-multilib`) and `execstack`. Use the Docker
image below for a clean Ubuntu 18.04 environment.

### Docker (Ubuntu 18.04 parity)

The base image must be pullable (some sandboxes block the registry CDN):

```sh
docker build -t bibifi .
# one-shot build inside the image:
docker run --rm bibifi bash -c 'cd build && make && execstack -q stor'
# iterative dev with a bind mount (no rebuild of the image):
docker run --rm -v "$PWD":/src bibifi bash -c 'cd build && make'
```

The Dockerfile repoints apt to `old-releases.ubuntu.com` first (18.04 is EOL)
and pre-stages `libsodium`/`libssl` i386 packages for the crypto pass.

## Usage

```
stor -u <user> (-k <key>) [register|create|write|read] (-f file) (-i infile) (-o outfile) <text>
```

| Command  | Requires        | Effect                                                        |
|----------|-----------------|--------------------------------------------------------------|
| register | `-u -k`         | create an account                                            |
| create   | `-u -f`         | create an empty file owned by the (already-registered) user  |
| write    | `-u -k -f`      | set file content; input from `-i` file, else inline text, else stdin |
| read     | `-u -k -f`      | output file content to `-o` file, else stdout                |

- Repeated named flags: **last occurrence wins** (`-k bad -k good` uses `good`).
- Any missing/contradictory/unknown argument, failed auth, or missing/duplicate
  resource prints `invalid` to stdout and exits **255**.

```sh
./stor -u alice -k secret123 register
./stor -u alice -f notes create
./stor -u alice -k secret123 -f notes write "Hello"
./stor -u alice -k secret123 -f notes read        # -> Hello
```

## Behavioral assumptions — **verify against the test suite**

These resolve spec ambiguities (we worked from the English spec; the rows tagged
`[verify]` in `args.c` validation are the riskiest). Each is easy to flip:

1. `read` writes content **verbatim, no added trailing newline** (`io.c`).
2. `register` success: no stdout, exit 0. Re-registering a user → `invalid`/255.
3. `create` requires the user to **already exist**; duplicate file → `invalid`/255.
   A stray `-k` on `create` is **ignored** (key not required).
4. Wrong key, or a missing / non-owned file, on `write`/`read` → `invalid`/255.
5. `write` input precedence: **`-i` file > inline text > stdin** (having more than
   one present is *not* an error). `-i` at a missing path → `invalid`/255. No input
   from any source → empty content (valid).
6. `read -o` overwrites an existing output file.
7. Missing `-u`, two commands, an unknown flag, or a flag missing its value →
   `invalid`/255.
8. Filenames are **per-user** (each user has its own namespace).
9. `fail()` prints `invalid` **with a trailing newline** (`puts`). If the grader
   wants an exact match with no newline, change it to `fputs("invalid", stdout)`
   in `stor.c`.
10. A command keyword used as inline write *text* (e.g. `write "read"`) is parsed
    as a second command → `invalid`. Quote-arbitrary content equal to a keyword is
    the one known edge case; revisit if a test exercises it.

## Security model

All crypto is in `db.c`; the on-disk layout is private to that file. The
command-line **key is a password** — it is never stored.

- **Key derivation.** `register` draws a random 16-byte salt and derives a
  256-bit key with **Argon2id** (`crypto_pwhash`, `*_INTERACTIVE` limits, stored
  per-user so the params can be retuned without breaking old records).
- **Password check.** A 16-byte token sealed under the derived key is stored as
  a *verifier*; `write`/`read` reject a wrong password by failing to open it —
  even on an empty file (no file content needed to authenticate).
- **File content.** Stored as `nonce || secretbox(K, plaintext)` — XSalsa20 +
  Poly1305 authenticated encryption under the **owner's** derived key. This gives
  per-record confidentiality *and* integrity: content cannot be read, tampered,
  forged, or moved to another user without that user's password. An empty
  (created-but-never-written) file stores zero bytes.

### Design note — why not sealed boxes / a global MAC

The draft plan proposed per-user keypairs + `crypto_box_seal` + a db-wide MAC.
The shipped design uses symmetric `secretbox` instead, deliberately:

- `create` (which takes no key) only ever makes an **empty** file, so the sole
  reason for sealing ("encrypt without the secret") never applies.
- Files are per-owner, so no one else writes to your files. Sealed boxes would
  let *anyone* holding your public key forge content into your files — an
  integrity hole. Owner-keyed `secretbox` authenticates content under a secret,
  closing it.
- There is no global secret (all secrets are per-user passwords), so there is
  nothing to key a global db MAC with. Per-record AE already defeats structural
  forgery and cross-user theft, which is verified in the test run.

> Offline password guessing is inherent to any server-less store; Argon2id is the
> mitigation. Bump to `*_MODERATE` limits in `db.c` (`db_add_user`) if the grader
> tolerates the extra per-call latency.

## Out of scope this pass (next)

- Break-It exploit tooling under `break/`.
