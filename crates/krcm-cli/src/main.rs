use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use krcm_core::{
    decrypt_auto, decrypt_v5, encrypt_v4, encrypt_v5, DecryptV5Options, EncryptV4Options,
    EncryptV5Options, KdfParams, KrcmError, PaddingPolicy,
};
use rand::RngCore;

const WARNING: &str = "KRCM-SPN is an experimental cryptographic construction. It is not a replacement for audited, standardized schemes such as AES-GCM, ChaCha20-Poly1305, age, GnuPG, or libsodium. Do not use it to protect production data, regulated data, financial secrets, credentials, or any information whose compromise would cause harm. The project is intended for research, experimentation, implementation practice, and review.";

#[derive(Parser)]
#[command(name = "krcm")]
#[command(about = "Experimental KRCM-SPN research CLI")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, ValueEnum)]
enum KdfChoice {
    Pbkdf2,
    Scrypt,
}

#[derive(Copy, Clone, ValueEnum)]
enum PaddingChoice {
    Minimal,
    #[value(name = "4k")]
    FourK,
    #[value(name = "64k")]
    SixtyFourK,
}

#[derive(Subcommand)]
enum Command {
    Encrypt {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        confirm_password: bool,
        #[arg(long, default_value_t = 4)]
        version: u8,
        #[arg(long, value_enum, default_value_t = KdfChoice::Pbkdf2)]
        kdf: KdfChoice,
        #[arg(long, default_value_t = 200_000)]
        pbkdf2_iterations: u32,
        #[arg(long, default_value_t = 14)]
        scrypt_n_log2: u8,
        #[arg(long, default_value_t = 8)]
        scrypt_r: u32,
        #[arg(long, default_value_t = 1)]
        scrypt_p: u32,
        #[arg(long, value_enum, default_value_t = PaddingChoice::Minimal)]
        padding: PaddingChoice,
        #[arg(long, default_value = "4M")]
        segment_size: String,
        #[arg(long, default_value_t = 1)]
        workers: usize,
    },
    Decrypt {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    Info {
        input: PathBuf,
    },
    Migrate {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value_t = 5)]
        to_version: u8,
    },
    SelfTest,
    Bench,
}

fn main() -> std::process::ExitCode {
    eprintln!("{WARNING}");
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), KrcmError> {
    match Args::parse().command {
        Command::Encrypt {
            input,
            output,
            force,
            confirm_password,
            version,
            kdf,
            pbkdf2_iterations,
            scrypt_n_log2,
            scrypt_r,
            scrypt_p,
            padding,
            segment_size,
            workers,
        } => {
            ensure_output_available(&output, force)?;
            let password = read_password(confirm_password)?;
            let data = fs::read(input)?;
            let encrypted = match version {
                4 => encrypt_v4(
                    &data,
                    password.as_bytes(),
                    EncryptV4Options {
                        iterations: pbkdf2_iterations,
                        ..EncryptV4Options::default()
                    },
                )?,
                5 => encrypt_v5(
                    &data,
                    password.as_bytes(),
                    EncryptV5Options {
                        kdf: make_kdf(kdf, pbkdf2_iterations, scrypt_n_log2, scrypt_r, scrypt_p),
                        padding_policy: make_padding(padding),
                        segment_size: parse_size(&segment_size)?,
                        workers,
                        salt: None,
                        public_nonce: None,
                    },
                )?,
                _ => return Err(KrcmError::UnsupportedVersion),
            };
            atomic_write(&output, &encrypted, force)
        }
        Command::Decrypt {
            input,
            output,
            force,
        } => {
            ensure_output_available(&output, force)?;
            let password = read_password(false)?;
            let data = fs::read(input)?;
            let decrypted = decrypt_auto(&data, password.as_bytes())?;
            atomic_write(&output, &decrypted, force)
        }
        Command::Info { input } => {
            let data = fs::read(input)?;
            if data.starts_with(krcm_core::constants::MAGIC_V4) {
                println!("format: KRCM-SPN v4 container (legacy format identifier AMPCRYPT)");
            } else if data.starts_with(krcm_core::constants::MAGIC_V5) {
                println!("format: KRCM-SPN v5 container");
            } else {
                return Err(KrcmError::Format);
            }
            Ok(())
        }
        Command::Migrate {
            input,
            output,
            force,
            to_version,
        } => {
            ensure_output_available(&output, force)?;
            if to_version != 5 {
                return Err(KrcmError::UnsupportedVersion);
            }
            let password = read_password(false)?;
            let source = fs::read(input)?;
            let plain = decrypt_auto(&source, password.as_bytes())?;
            let migrated = encrypt_v5(
                &plain,
                password.as_bytes(),
                EncryptV5Options {
                    kdf: KdfParams::Pbkdf2 {
                        iterations: 200_000,
                    },
                    padding_policy: PaddingPolicy::MinimalBlock,
                    segment_size: 4 * 1024 * 1024,
                    workers: 1,
                    salt: None,
                    public_nonce: None,
                },
            )?;
            if decrypt_v5(&migrated, password.as_bytes(), DecryptV5Options)? != plain {
                return Err(KrcmError::Internal);
            }
            atomic_write(&output, &migrated, force)
        }
        Command::SelfTest => {
            let data = b"krcm self test";
            let password = b"self-test-password";
            let encrypted = encrypt_v5(
                data,
                password,
                EncryptV5Options {
                    kdf: KdfParams::Pbkdf2 { iterations: 1_000 },
                    padding_policy: PaddingPolicy::MinimalBlock,
                    segment_size: 128,
                    workers: 2,
                    salt: Some([1u8; 16]),
                    public_nonce: Some([2u8; 16]),
                },
            )?;
            let decrypted = decrypt_auto(&encrypted, password)?;
            if decrypted != data {
                return Err(KrcmError::Internal);
            }
            Ok(())
        }
        Command::Bench => {
            let data = vec![0x42u8; 1024];
            let start = Instant::now();
            let encrypted = encrypt_v5(
                &data,
                b"bench-password",
                EncryptV5Options {
                    kdf: KdfParams::Pbkdf2 { iterations: 1_000 },
                    padding_policy: PaddingPolicy::MinimalBlock,
                    segment_size: 1024,
                    workers: 1,
                    salt: Some([7u8; 16]),
                    public_nonce: Some([8u8; 16]),
                },
            )?;
            let elapsed = start.elapsed();
            let _ = decrypt_auto(&encrypted, b"bench-password")?;
            println!("bench_v5_encrypt_1k_debug: {} us", elapsed.as_micros());
            Ok(())
        }
    }
}

fn make_kdf(choice: KdfChoice, pbkdf2_iterations: u32, n_log2: u8, r: u32, p: u32) -> KdfParams {
    match choice {
        KdfChoice::Pbkdf2 => KdfParams::Pbkdf2 {
            iterations: pbkdf2_iterations,
        },
        KdfChoice::Scrypt => KdfParams::Scrypt { n_log2, r, p },
    }
}

fn make_padding(choice: PaddingChoice) -> PaddingPolicy {
    match choice {
        PaddingChoice::Minimal => PaddingPolicy::MinimalBlock,
        PaddingChoice::FourK => PaddingPolicy::RandomBlocks { max_blocks: 15 },
        PaddingChoice::SixtyFourK => PaddingPolicy::RandomBlocks { max_blocks: 15 },
    }
}

fn parse_size(value: &str) -> Result<usize, KrcmError> {
    let upper = value.trim().to_ascii_uppercase();
    let (number, multiplier) = if let Some(number) = upper.strip_suffix('M') {
        (number, 1024usize * 1024)
    } else if let Some(number) = upper.strip_suffix('K') {
        (number, 1024usize)
    } else {
        (upper.as_str(), 1usize)
    };
    number
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|&n| n > 0)
        .ok_or(KrcmError::InvalidParameter)
}

fn read_password(confirm: bool) -> Result<String, KrcmError> {
    let password = rpassword::prompt_password("Password: ").map_err(|_| KrcmError::Io)?;
    if password.is_empty() {
        return Err(KrcmError::InvalidPassword);
    }
    if confirm {
        let repeated =
            rpassword::prompt_password("Repeat password: ").map_err(|_| KrcmError::Io)?;
        if password != repeated {
            return Err(KrcmError::InvalidPassword);
        }
    }
    Ok(password)
}

fn ensure_output_available(path: &Path, force: bool) -> Result<(), KrcmError> {
    if path.exists() && !force {
        return Err(KrcmError::Io);
    }
    Ok(())
}

fn atomic_write(path: &Path, data: &[u8], force: bool) -> Result<(), KrcmError> {
    ensure_output_available(path, force)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut rng = rand::thread_rng();
    let mut tmp_path;
    let mut file;
    loop {
        let suffix = rng.next_u64();
        tmp_path = directory.join(format!(
            ".{}.{}.tmp",
            path.file_name().unwrap().to_string_lossy(),
            suffix
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(handle) => {
                file = handle;
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(KrcmError::Io),
        }
    }
    let result = (|| {
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&tmp_path, path)?;
        if let Ok(dir) = OpenOptions::new().read(true).open(directory) {
            let _ = dir.sync_all();
        }
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
        return Err(KrcmError::Io);
    }
    Ok(())
}
