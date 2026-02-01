# apropos-rs

Multithreaded full-text search over manpages (similar to `man -K`).

This searches the *source* manpage files found via `MANPATH`/`manpath`, including
compressed pages (`.gz`, `.bz2`, `.xz`, `.zst`).

## Install

From a checkout:

```sh
cargo install --path .
```

## Usage

```sh
apropos-rs [OPTIONS] <PATTERN>
```

Examples:

```sh
# Regex search (default)
apropos-rs 'openat2\\('

# Fixed-string search
apropos-rs -F '7-Zip'

# Fixed-string search (case-insensitive)
apropos-rs -F -i '7-zip'

# Search only section 1 and 8 manpages
apropos-rs -s 1,8 -F 'systemd'

# Print matching file paths instead of "name (section)"
apropos-rs -w -F 'printf'
```

## Notes

- The `-j/--jobs` option limits the number of worker threads used for searching.
- If `MANPATH` is unset, the tool tries to obtain a default path from `manpath`
  or `man --path`, falling back to common locations like `/usr/share/man`.

