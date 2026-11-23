# C / C++ / Objective-C (also unsafe Rust and cgo)

## Sources
- `argv`, `getenv`, `stdin` (`fgets`, `scanf`, `getline`, `read(0, ...)`), sockets (`recv`, `recvfrom`, `read` on fds), files (`fread`, `mmap`), IPC/shared memory, parsed packet/file headers (length fields!), environment in setuid programs

## Sinks
| Class | Sinks |
|---|---|
| Buffer overflow (CWE-120/787) | `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets` (always vulnerable), `scanf("%s")`, `wcscpy`, `lstrcpy`, `memcpy/memmove` with an attacker length, `strncpy` misuse (no NUL termination), array indexing with an unchecked index, `alloca(user)`, VLAs sized by input |
| Format string (CWE-134) | `printf(user)`, `fprintf(f, user)`, `sprintf(buf, user)`, `snprintf(buf, n, user)`, `syslog(prio, user)`, `err/warn(user)` |
| Integer issues (CWE-190/191) | `malloc(n * size)` without an overflow check, signed/unsigned comparison of lengths, `size_t` underflow (`len - header`), truncation `int` ← `size_t` |
| Memory lifetime (CWE-416/415/476) | use after `free`, double free on error paths, returning pointers to stack memory, missing NULL checks after `malloc`/`realloc`, `realloc` result assigned to the same pointer (leak and NULL) |
| Command | `system`, `popen`, `exec*` with a shell, `ShellExecute`, `WinExec`, `CreateProcess` with an unquoted path (CWE-428) |
| Path / race | `fopen(user)`, `access()` then `open()` (TOCTOU, CWE-367), `tmpnam/tempnam/mktemp` (CWE-377), `chmod 0777` |
| Crypto | `rand/srand(time(NULL))` for keys or tokens; hard-coded keys; OpenSSL `SSL_CTX_set_verify(..., SSL_VERIFY_NONE, ...)`; `EVP_des_*`, `EVP_rc4`, `*_ecb` |

## Tracing tips
- For every copy or write sink, identify **destination size** and **source length**, and trace both back. A finding needs the attacker to control the length or content **and** no bound check on the path.
- Check off-by-one: `buf[sizeof(buf)] = 0`, `<=` loops, `strncat(dst, src, sizeof(dst))` (wrong: needs the remaining space − 1).
- Error paths: `goto cleanup` that frees twice; early returns that leak or leave dangling pointers.
- Parsers: length fields read from input used directly for `memcpy`/allocation → classic heap overflow.

## Safe alternatives
`snprintf` (check the return value), `strlcpy/strlcat` or `strcpy_s`, `fgets` instead of `gets`, `printf("%s", s)`, `calloc` or checked multiplication (`__builtin_mul_overflow`), `std::string`/`std::vector`/`std::span`, `.at()` bounds checks, smart pointers, `mkstemp`, `execve` with an argument vector, `getrandom()`/`arc4random`/`RAND_bytes`, `SSL_VERIFY_PEER`.

## Unsafe Rust / cgo
- `unsafe {}` blocks: raw pointer deref, `from_raw_parts` with untrusted lengths, `transmute`, `set_len`, FFI boundaries. Check invariants around each block.
- Rust `Command::new("sh").arg("-c").arg(user)` → command injection; `format!` into SQL (`sqlx::query(&format!(...))`) → SQLi (use `query!`/`bind`).
