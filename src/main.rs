use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Parser};
use memchr::memmem;
use rayon::prelude::*;
use regex::RegexBuilder;
use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(
    name = "apropos-rs",
    about = "Multithreaded full-text search over manpages (man -K style)",
    version
)]
#[command(group(
    ArgGroup::new("mode")
        .args(["fixed_string", "regex"])
        .multiple(false)
        .required(false)
))]
struct Opts {
    /// Pattern to search for
    pattern: String,

    /// Use fixed-string search (default is regex)
    #[arg(short = 'F', long = "fixed-string")]
    fixed_string: bool,

    /// Force regex search (default)
    #[arg(short = 'r', long = "regex")]
    regex: bool,

    /// Ignore case distinctions
    #[arg(short, long)]
    ignore_case: bool,

    /// Restrict search to specific sections (comma/colon separated). Can be repeated.
    #[arg(short = 's', long = "section")]
    sections: Vec<String>,

    /// Override MANPATH (colon-separated list)
    #[arg(short = 'M', long = "manpath")]
    manpath: Option<String>,

    /// Print matching file paths instead of names
    #[arg(short = 'w', long = "where")]
    where_path: bool,

    /// Number of worker threads
    #[arg(short = 'j', long = "jobs")]
    jobs: Option<usize>,
}

#[derive(Default)]
struct WarningTracker {
    shown: usize,
    suppressed: usize,
}

impl WarningTracker {
    const LIMIT: usize = 20;

    fn warn(&mut self, message: impl fmt::Display) {
        if self.shown < Self::LIMIT {
            eprintln!("warning: {message}");
            self.shown += 1;
        } else {
            self.suppressed += 1;
        }
    }

    fn finish(&mut self) {
        if self.suppressed > 0 {
            eprintln!("warning: suppressed {} more warnings", self.suppressed);
        }
    }
}

enum Matcher {
    Regex(regex::Regex),
    FixedBytes { needle: Vec<u8> },
    FixedAsciiCaseInsensitive { needle_lower: Vec<u8> },
    FixedUnicodeCaseInsensitive(regex::Regex),
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let opts = Opts::parse();

    let matcher = build_matcher(&opts)?;
    let sections = parse_sections(&opts.sections);
    let manpaths = resolve_manpaths(opts.manpath.as_deref());
    let mut traversal_warnings = WarningTracker::default();
    let man_dirs = collect_man_dirs(&manpaths, &sections, &mut traversal_warnings);
    let files = collect_man_files(&man_dirs, &mut traversal_warnings);
    traversal_warnings.finish();

    let search = || {
        let mut matches: Vec<PathBuf> = files
            .par_iter()
            .filter_map(|path| match search_file(path, &matcher) {
                Ok(true) => Some(path.clone()),
                Ok(false) => None,
                Err(err) => {
                    eprintln!("warning: {}: {err}", path.display());
                    None
                }
            })
            .collect();
        matches.sort();
        matches
    };

    let matches = match opts.jobs {
        Some(0) => bail!("--jobs must be greater than 0"),
        Some(jobs) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(jobs)
                .build()
                .context("failed to configure thread pool")?;
            pool.install(search)
        }
        None => search(),
    };

    for path in matches {
        println!("{}", format_match(&path, opts.where_path));
    }

    Ok(())
}

fn build_matcher(opts: &Opts) -> Result<Matcher> {
    let use_fixed = match (opts.fixed_string, opts.regex) {
        (true, _) => true,
        (false, true) => false,
        (false, false) => false,
    };

    if use_fixed {
        if opts.ignore_case {
            if opts.pattern.is_ascii() {
                let needle_lower = opts
                    .pattern
                    .as_bytes()
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect();
                Ok(Matcher::FixedAsciiCaseInsensitive { needle_lower })
            } else {
                let escaped = regex::escape(&opts.pattern);
                let mut builder = RegexBuilder::new(&escaped);
                builder.case_insensitive(true);
                let regex = builder
                    .build()
                    .context("failed to compile case-insensitive fixed-string matcher")?;
                Ok(Matcher::FixedUnicodeCaseInsensitive(regex))
            }
        } else {
            Ok(Matcher::FixedBytes {
                needle: opts.pattern.as_bytes().to_vec(),
            })
        }
    } else {
        let mut builder = RegexBuilder::new(&opts.pattern);
        builder.case_insensitive(opts.ignore_case);
        let regex = builder.build().context("invalid regex pattern")?;
        Ok(Matcher::Regex(regex))
    }
}

fn parse_sections(raw: &[String]) -> HashSet<String> {
    let mut sections = HashSet::new();
    for item in raw {
        for part in item
            .split(|c: char| c == ',' || c == ':' || c.is_whitespace())
            .filter(|part| !part.is_empty())
        {
            sections.insert(part.to_string());
        }
    }
    sections
}

fn resolve_manpaths(override_path: Option<&str>) -> Vec<PathBuf> {
    if let Some(value) = override_path {
        return expand_manpath_value(value, || system_manpaths().unwrap_or_else(default_manpaths));
    }

    match env::var("MANPATH") {
        Ok(value) => expand_manpath_value(&value, || {
            system_manpaths().unwrap_or_else(default_manpaths)
        }),
        Err(_) => system_manpaths().unwrap_or_else(default_manpaths),
    }
}

fn expand_manpath_value<F>(value: &str, default_provider: F) -> Vec<PathBuf>
where
    F: FnOnce() -> Vec<PathBuf>,
{
    if value.is_empty() {
        return Vec::new();
    }

    // According to man(1), if MANPATH starts with a colon, the default path is prepended.
    // If it ends with a colon, the default path is appended.
    // If it contains a double colon, the default path is inserted at that point.
    // value.split(':') will give empty strings for these cases.
    let parts: Vec<&str> = value.split(':').collect();
    let needs_default = parts.iter().any(|part| part.is_empty());
    if !needs_default {
        return normalize_paths(parts.into_iter().map(PathBuf::from).collect());
    }

    let defaults = default_provider();
    let mut out = Vec::new();
    for part in parts {
        if part.is_empty() {
            out.extend(defaults.iter().cloned());
        } else {
            out.push(PathBuf::from(part));
        }
    }

    normalize_paths(out)
}

fn system_manpaths() -> Option<Vec<PathBuf>> {
    if let Some(paths) = run_manpath_command("manpath", &["-q"]) {
        return Some(paths);
    }
    run_manpath_command("man", &["--path"])
}

fn run_manpath_command(cmd: &str, args: &[&str]) -> Option<Vec<PathBuf>> {
    let output = Command::new(cmd)
        .args(args)
        .env_remove("MANPATH")
        .env_remove("MANOPT")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let paths = normalize_paths(raw.trim().split(':').map(PathBuf::from).collect());
    if paths.is_empty() { None } else { Some(paths) }
}

fn default_manpaths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for candidate in [
        "/usr/local/share/man",
        "/usr/share/man",
        "/usr/local/man",
        "/opt/homebrew/share/man",
        "/opt/local/share/man",
    ] {
        paths.push(PathBuf::from(candidate));
    }
    normalize_paths(paths)
}

fn normalize_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        if path.as_os_str().is_empty() {
            continue;
        }
        // If the path exists, we canonicalize it to handle symlinks and ensure uniqueness.
        // If it doesn't exist, we still keep it if it's not a duplicate of what we've seen.
        if let Ok(real_path) = path.canonicalize() {
            if seen.insert(real_path) {
                out.push(path);
            }
        } else if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

fn is_selected_man_section_dir(path: &Path, sections: &HashSet<String>) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    if !name.starts_with("man") || name.len() <= 3 {
        return false;
    }
    let section = &name[3..];
    sections.is_empty() || sections.contains(section)
}

fn preferred_locale_dirs() -> HashSet<String> {
    fn add_candidates(value: &str, out: &mut HashSet<String>) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }

        let (before_mod, modifier) = match value.split_once('@') {
            Some((before, modifier)) => (before, Some(modifier)),
            None => (value, None),
        };

        let (base, codeset) = match before_mod.split_once('.') {
            Some((base, codeset)) => (base, Some(codeset)),
            None => (before_mod, None),
        };

        if !base.is_empty() {
            out.insert(base.to_string());
        }
        if let Some(codeset) = codeset {
            out.insert(format!("{base}.{codeset}"));
        }
        if let Some(modifier) = modifier {
            out.insert(format!("{base}@{modifier}"));
            if let Some(codeset) = codeset {
                out.insert(format!("{base}.{codeset}@{modifier}"));
            }
        }

        let lang = base.split_once('_').map(|(lang, _)| lang).unwrap_or(base);
        if lang != base {
            out.insert(lang.to_string());
            if let Some(codeset) = codeset {
                out.insert(format!("{lang}.{codeset}"));
            }
            if let Some(modifier) = modifier {
                out.insert(format!("{lang}@{modifier}"));
                if let Some(codeset) = codeset {
                    out.insert(format!("{lang}.{codeset}@{modifier}"));
                }
            }
        }
    }

    let mut out = HashSet::new();

    // `LANGUAGE` is a colon-separated priority list (common on GNU systems).
    if let Ok(language) = env::var("LANGUAGE") {
        for part in language.split(':') {
            add_candidates(part, &mut out);
        }
    }

    // Locale env var precedence (roughly matches common expectations).
    let locale = env::var("LC_ALL")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            env::var("LC_MESSAGES")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .or_else(|| env::var("LANG").ok().filter(|value| !value.is_empty()));
    if let Some(locale) = locale {
        add_candidates(&locale, &mut out);
    }

    out
}

fn collect_man_dirs(
    manpaths: &[PathBuf],
    sections: &HashSet<String>,
    warnings: &mut WarningTracker,
) -> Vec<PathBuf> {
    let preferred_locales = preferred_locale_dirs();
    let mut seen = HashSet::new();
    let mut dirs = Vec::new();

    for base in manpaths {
        // Allow passing a section dir directly (e.g. /usr/share/man/man1).
        if is_selected_man_section_dir(base, sections) {
            if let Ok(real_base) = base.canonicalize() {
                if seen.insert(real_base) {
                    dirs.push(base.clone());
                }
            }
        }

        let entries = match fs::read_dir(base) {
            Ok(entries) => entries,
            Err(err) => {
                warnings.warn(format!(
                    "{}: failed to read directory: {err}",
                    base.display()
                ));
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warnings.warn(format!(
                        "{}: failed to read directory entry: {err}",
                        base.display()
                    ));
                    continue;
                }
            };
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if is_selected_man_section_dir(&path, sections) {
                if let Ok(real_path) = path.canonicalize() {
                    if seen.insert(real_path) {
                        dirs.push(path);
                    }
                }
                continue;
            }

            let Some(locale) = path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if !preferred_locales.contains(locale) {
                continue;
            }

            // Many distros place localized manpages under <root>/<locale>/manN. Only traverse
            // locales relevant to the current environment to avoid scanning every translation.
            let locale_entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(err) => {
                    warnings.warn(format!(
                        "{}: failed to read directory: {err}",
                        path.display()
                    ));
                    continue;
                }
            };

            for locale_entry in locale_entries {
                let locale_entry = match locale_entry {
                    Ok(entry) => entry,
                    Err(err) => {
                        warnings.warn(format!(
                            "{}: failed to read directory entry: {err}",
                            path.display()
                        ));
                        continue;
                    }
                };
                let locale_path = locale_entry.path();
                if !locale_path.is_dir() {
                    continue;
                }
                if is_selected_man_section_dir(&locale_path, sections) {
                    if let Ok(real_locale_path) = locale_path.canonicalize() {
                        if seen.insert(real_locale_path) {
                            dirs.push(locale_path);
                        }
                    }
                }
            }
        }
    }

    dirs
}

fn collect_man_files(man_dirs: &[PathBuf], warnings: &mut WarningTracker) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in man_dirs {
        for entry in WalkDir::new(dir).follow_links(true).min_depth(1).max_depth(1) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warnings.warn(format!("{}: {err}", dir.display()));
                    continue;
                }
            };
            if entry.file_type().is_file() {
                files.push(entry.path().to_path_buf());
            }
        }
    }
    files
}

fn search_file(path: &Path, matcher: &Matcher) -> Result<bool> {
    match matcher {
        Matcher::Regex(re) => {
            let bytes = read_man_file_bytes(path)?;
            let text = String::from_utf8_lossy(&bytes);
            Ok(re.is_match(text.as_ref()))
        }
        Matcher::FixedBytes { needle } => {
            let mut reader = open_man_reader(path)?;
            search_reader_bytes_sensitive(reader.as_mut(), needle)
                .with_context(|| format!("failed to read {}", path.display()))
        }
        Matcher::FixedAsciiCaseInsensitive { needle_lower } => {
            let mut reader = open_man_reader(path)?;
            search_reader_bytes_ascii_case_insensitive(reader.as_mut(), needle_lower)
                .with_context(|| format!("failed to read {}", path.display()))
        }
        Matcher::FixedUnicodeCaseInsensitive(re) => {
            let bytes = read_man_file_bytes(path)?;
            let text = String::from_utf8_lossy(&bytes);
            Ok(re.is_match(text.as_ref()))
        }
    }
}

fn open_man_reader(path: &Path) -> Result<Box<dyn Read>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    let reader: Box<dyn Read> = match path.extension().and_then(OsStr::to_str) {
        Some("gz") => Box::new(flate2::read::GzDecoder::new(file)),
        Some("bz2") => Box::new(bzip2::read::BzDecoder::new(file)),
        Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
        Some("zst") => Box::new(
            zstd::stream::read::Decoder::new(file)
                .with_context(|| format!("failed to create zstd decoder for {}", path.display()))?,
        ),
        _ => Box::new(file),
    };

    Ok(reader)
}

fn read_man_file_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut reader = open_man_reader(path)?;
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(buf)
}

const SEARCH_BUF_SIZE: usize = 64 * 1024;

fn search_reader_bytes_sensitive(reader: &mut dyn Read, needle: &[u8]) -> io::Result<bool> {
    if needle.is_empty() {
        return Ok(true);
    }

    let finder = memmem::Finder::new(needle);
    let keep = needle.len().saturating_sub(1);

    let mut buf = vec![0_u8; SEARCH_BUF_SIZE];
    let mut work = Vec::<u8>::new();
    let mut carry = Vec::<u8>::new();

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let chunk = &buf[..n];
        if carry.is_empty() {
            if finder.find(chunk).is_some() {
                return Ok(true);
            }
        } else {
            work.clear();
            work.extend_from_slice(&carry);
            work.extend_from_slice(chunk);
            if finder.find(&work).is_some() {
                return Ok(true);
            }
        }

        if keep > 0 {
            let src: &[u8] = if carry.is_empty() { chunk } else { &work };
            let tail_len = keep.min(src.len());
            carry.clear();
            carry.extend_from_slice(&src[src.len() - tail_len..]);
        }
    }

    Ok(false)
}

fn search_reader_bytes_ascii_case_insensitive(
    reader: &mut dyn Read,
    needle_lower: &[u8],
) -> io::Result<bool> {
    if needle_lower.is_empty() {
        return Ok(true);
    }

    let finder = memmem::Finder::new(needle_lower);
    let keep = needle_lower.len().saturating_sub(1);

    let mut buf = vec![0_u8; SEARCH_BUF_SIZE];
    let mut chunk_lower = Vec::<u8>::new();
    let mut work = Vec::<u8>::new();
    let mut carry = Vec::<u8>::new();

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }

        chunk_lower.resize(n, 0);
        for (dst, src) in chunk_lower.iter_mut().zip(&buf[..n]) {
            *dst = src.to_ascii_lowercase();
        }

        if carry.is_empty() {
            if finder.find(&chunk_lower).is_some() {
                return Ok(true);
            }
        } else {
            work.clear();
            work.extend_from_slice(&carry);
            work.extend_from_slice(&chunk_lower);
            if finder.find(&work).is_some() {
                return Ok(true);
            }
        }

        if keep > 0 {
            let src: &[u8] = if carry.is_empty() {
                &chunk_lower
            } else {
                &work
            };
            let tail_len = keep.min(src.len());
            carry.clear();
            carry.extend_from_slice(&src[src.len() - tail_len..]);
        }
    }

    Ok(false)
}

fn format_match(path: &Path, where_path: bool) -> String {
    if where_path {
        return path.display().to_string();
    }

    let (name, section) = parse_name_section(path);
    match section {
        Some(section) => format!("{} ({})", name, section),
        None => name,
    }
}

fn parse_name_section(path: &Path) -> (String, Option<String>) {
    let filename = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("")
        .to_string();

    let base = strip_compression_extension(&filename);
    if let Some((name, section)) = base.rsplit_once('.') {
        (name.to_string(), Some(section.to_string()))
    } else {
        (base, None)
    }
}

fn strip_compression_extension(filename: &str) -> String {
    for ext in [".gz", ".bz2", ".xz", ".zst"] {
        if let Some(stripped) = filename.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    filename.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let mut path = std::env::temp_dir();
            let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            path.push(format!(
                "apropos-rs-test-{prefix}-{}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn parse_sections_splits_on_commas_colons_and_whitespace() {
        let raw = vec!["1, 8: 3\t2".to_string(), "3".to_string()];
        let sections = parse_sections(&raw);
        for expected in ["1", "2", "3", "8"] {
            assert!(sections.contains(expected));
        }
    }

    #[test]
    fn strip_compression_extension_strips_known_extensions() {
        assert_eq!(strip_compression_extension("foo.1.gz"), "foo.1");
        assert_eq!(strip_compression_extension("foo.1.bz2"), "foo.1");
        assert_eq!(strip_compression_extension("foo.1.xz"), "foo.1");
        assert_eq!(strip_compression_extension("foo.1.zst"), "foo.1");
        assert_eq!(strip_compression_extension("foo.1"), "foo.1");
    }

    #[test]
    fn search_reader_bytes_sensitive_finds_across_chunk_boundary() {
        let mut content = vec![b'a'; SEARCH_BUF_SIZE - 1];
        content.push(b'x');
        content.push(b'y');

        let mut cursor = Cursor::new(content);
        assert!(search_reader_bytes_sensitive(&mut cursor, b"xy").unwrap());
    }

    #[test]
    fn search_reader_bytes_ascii_case_insensitive_finds_across_chunk_boundary() {
        let mut content = vec![b'a'; SEARCH_BUF_SIZE - 1];
        content.push(b'X');
        content.push(b'y');

        let mut cursor = Cursor::new(content);
        assert!(search_reader_bytes_ascii_case_insensitive(&mut cursor, b"xy").unwrap());
    }

    #[test]
    fn search_reader_bytes_ascii_case_insensitive_returns_false_when_no_match() {
        let mut cursor = Cursor::new(b"abcdef".to_vec());
        assert!(
            !search_reader_bytes_ascii_case_insensitive(&mut cursor, b"xyz").unwrap(),
            "expected no match"
        );
    }

    #[test]
    fn collect_man_dirs_accepts_section_dir_in_manpath() {
        let tmp = TempDir::new("mandirs-section");
        let man1 = tmp.path.join("man1");
        fs::create_dir_all(&man1).unwrap();

        let mut warnings = WarningTracker::default();
        let dirs = collect_man_dirs(&[man1.clone()], &HashSet::new(), &mut warnings);
        assert!(dirs.contains(&man1));
    }

    #[test]
    fn collect_man_dirs_filters_by_section() {
        let tmp = TempDir::new("mandirs-filter");
        let root = tmp.path.join("root");
        let man1 = root.join("man1");
        let man8 = root.join("man8");
        fs::create_dir_all(&man1).unwrap();
        fs::create_dir_all(&man8).unwrap();

        let mut sections = HashSet::new();
        sections.insert("8".to_string());

        let mut warnings = WarningTracker::default();
        let dirs = collect_man_dirs(&[root], &sections, &mut warnings);
        assert!(dirs.contains(&man8));
        assert!(!dirs.contains(&man1));
    }

    #[test]
    fn collect_man_files_includes_symlinked_manpages() {
        let tmp = TempDir::new("manfiles-symlink");
        let man1 = tmp.path.join("man1");
        fs::create_dir_all(&man1).unwrap();

        let real = man1.join("foo.1");
        fs::write(&real, b"hello").unwrap();

        let link = man1.join("bar.1");
        // Use a relative target to keep the symlink valid if the test directory moves.
        symlink("foo.1", &link).unwrap();

        let mut warnings = WarningTracker::default();
        let files = collect_man_files(&[man1], &mut warnings);
        assert!(files.contains(&real));
        assert!(files.contains(&link));
    }

    #[test]
    fn expand_manpath_value_handles_leading_trailing_and_double_colons() {
        let defaults = vec![PathBuf::from("/def1"), PathBuf::from("/def2")];
        let provider = || defaults.clone();

        // Leading colon
        let paths = expand_manpath_value(":/extra", provider);
        assert_eq!(paths[0], PathBuf::from("/def1"));
        assert_eq!(paths[1], PathBuf::from("/def2"));
        assert_eq!(paths[2], PathBuf::from("/extra"));

        // Trailing colon
        let paths = expand_manpath_value("/extra:", provider);
        assert_eq!(paths[0], PathBuf::from("/extra"));
        assert_eq!(paths[1], PathBuf::from("/def1"));
        assert_eq!(paths[2], PathBuf::from("/def2"));

        // Double colon
        let paths = expand_manpath_value("/extra1::/extra2", provider);
        assert_eq!(paths[0], PathBuf::from("/extra1"));
        assert_eq!(paths[1], PathBuf::from("/def1"));
        assert_eq!(paths[2], PathBuf::from("/def2"));
        assert_eq!(paths[3], PathBuf::from("/extra2"));
    }
}
