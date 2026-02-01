use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};
use rayon::prelude::*;
use regex::RegexBuilder;
use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
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

enum Matcher {
    Regex(regex::Regex),
    Fixed {
        needle: String,
        needle_lower: String,
        ignore_case: bool,
    },
}

impl Matcher {
    fn is_match(&self, haystack: &str) -> bool {
        match self {
            Matcher::Regex(re) => re.is_match(haystack),
            Matcher::Fixed {
                needle,
                needle_lower,
                ignore_case,
            } => {
                if *ignore_case {
                    haystack.to_lowercase().contains(needle_lower)
                } else {
                    haystack.contains(needle)
                }
            }
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let opts = Opts::parse();

    if let Some(jobs) = opts.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global()
            .context("failed to configure thread pool")?;
    }

    let matcher = build_matcher(&opts)?;
    let sections = parse_sections(&opts.sections);
    let manpaths = resolve_manpaths(opts.manpath.as_deref());
    let man_dirs = collect_man_dirs(&manpaths, &sections);
    let files = collect_man_files(&man_dirs);

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
        Ok(Matcher::Fixed {
            needle: opts.pattern.clone(),
            needle_lower: opts.pattern.to_lowercase(),
            ignore_case: opts.ignore_case,
        })
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
        if path.is_dir() && seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

fn collect_man_dirs(manpaths: &[PathBuf], sections: &HashSet<String>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for base in manpaths {
        let entries = match fs::read_dir(base) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = match path.file_name().and_then(OsStr::to_str) {
                Some(name) => name,
                None => continue,
            };
            if !name.starts_with("man") || name.len() <= 3 {
                continue;
            }
            let section = &name[3..];
            if sections.is_empty() || sections.contains(section) {
                dirs.push(path);
            }
        }
    }

    dirs
}

fn collect_man_files(man_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in man_dirs {
        for entry in WalkDir::new(dir)
            .min_depth(1)
            .max_depth(1)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                files.push(entry.path().to_path_buf());
            }
        }
    }
    files
}

fn search_file(path: &Path, matcher: &Matcher) -> Result<bool> {
    let content = read_man_file(path)?;
    Ok(matcher.is_match(&content))
}

fn read_man_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    let mut reader: Box<dyn Read> = match path.extension().and_then(OsStr::to_str) {
        Some("gz") => Box::new(flate2::read::GzDecoder::new(file)),
        Some("bz2") => Box::new(bzip2::read::BzDecoder::new(file)),
        Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
        Some("zst") => Box::new(zstd::stream::read::Decoder::new(file)?),
        _ => Box::new(file),
    };

    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read {}", path.display()))?;

    Ok(String::from_utf8_lossy(&buf).into_owned())
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
