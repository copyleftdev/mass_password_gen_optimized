use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rayon::prelude::*;
use std::time::Instant;
use sysinfo::{CpuExt, System, SystemExt};

// Each password is 16 bytes
type PasswordBlock = [u8; 16];

// Our AES-CTR type: 128-bit block size, big-endian counter
type Aes128Ctr = Ctr128BE<Aes128>;

// Adjust these if desired
const NUM_PASSWORDS: usize = 4_000_000_000; // e.g. 1 billion
const CHUNK_SIZE: usize = 1_000_000;       // 1 million => 16 MB per chunk

fn main() {
    // ------------------------------------------------------------------
    // 1. Gather system details before we begin
    // ------------------------------------------------------------------
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU details
    let cpu_count = sys.cpus().len();
    // On many systems, sysinfo lumps hyperthreads into the CPU count.
    let brand = if cpu_count > 0 {
        sys.cpus()[0].brand().to_string()
    } else {
        "Unknown CPU".into()
    };

    // Memory in KiB -> GiB conversion (1 GiB = 1024 * 1024 KiB)
    let total_mem_gib = sys.total_memory() as f64 / (1024.0 * 1024.0);
    let used_mem_gib = sys.used_memory() as f64 / (1024.0 * 1024.0);

    // OS name/version if available
    let os_name = sys.name().unwrap_or_else(|| "Unknown OS".to_string());
    let os_version = sys.os_version().unwrap_or_else(|| "Unknown".to_string());
    let kernel_version = sys.kernel_version().unwrap_or_else(|| "Unknown".to_string());

    println!("=== System Information ===");
    println!("OS: {} (version: {}), kernel: {}", os_name, os_version, kernel_version);
    println!("CPU Count: {}", cpu_count);
    println!("CPU Brand: {}", brand);
    println!("Total Memory: {:.2} GiB", total_mem_gib);
    println!("Used Memory:  {:.2} GiB", used_mem_gib);
    println!("==========================\n");

    // ------------------------------------------------------------------
    // 2. Prepare to generate N passwords
    // ------------------------------------------------------------------
    if NUM_PASSWORDS % CHUNK_SIZE != 0 {
        panic!(
            "NUM_PASSWORDS ({}) must be divisible by CHUNK_SIZE ({})",
            NUM_PASSWORDS, CHUNK_SIZE
        );
    }

    println!(
        "Allocating space for {} passwords (~{:.2} GiB)...",
        NUM_PASSWORDS,
        (NUM_PASSWORDS as f64 * 16.0) / (1024.0 * 1024.0 * 1024.0)
    );

    let mut passwords = Vec::<PasswordBlock>::with_capacity(NUM_PASSWORDS);
    // We will overwrite every byte, so skip zero init:
    unsafe { passwords.set_len(NUM_PASSWORDS); }

    let num_chunks = NUM_PASSWORDS / CHUNK_SIZE;
    println!(
        "Generating in {} parallel chunks of {} passwords each...\n",
        num_chunks, CHUNK_SIZE
    );

    // Example key (use randomness in production)
    let key = [0x13_u8; 16];

    // ------------------------------------------------------------------
    // 3. Time the generation
    // ------------------------------------------------------------------
    let start_time = Instant::now();

    passwords
        .par_chunks_mut(CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            // chunk is &mut [[u8;16]]
            let byte_len = chunk.len() * 16;
            let chunk_ptr = chunk.as_mut_ptr() as *mut u8;
            let chunk_bytes = unsafe { std::slice::from_raw_parts_mut(chunk_ptr, byte_len) };

            // Construct a unique IV for each chunk to avoid overlap
            let mut iv = [0u8; 16];
            // For example, embed chunk_idx in the last 8 bytes, little-endian:
            iv[8..16].copy_from_slice(&chunk_idx.to_le_bytes());

            // Create AES-CTR instance
            let mut cipher = Aes128Ctr::new(&key.into(), &iv.into());
            // Fill chunk in one shot
            cipher.apply_keystream(chunk_bytes);
        });

    let duration = start_time.elapsed();

    // ------------------------------------------------------------------
    // 4. Refresh system info again (optional) and print stats
    // ------------------------------------------------------------------
    sys.refresh_all();
    let used_mem_after_gib = sys.used_memory() as f64 / (1024.0 * 1024.0);

    println!(
        "Generated {} unique, 128-bit passwords in {:.2?}",
        NUM_PASSWORDS, duration
    );
    let secs = duration.as_secs_f64();
    let rate = (NUM_PASSWORDS as f64) / secs;
    println!(
        "Rate: ~{:.0} passwords/sec (~{:.1} million/sec)",
        rate,
        rate / 1_000_000.0
    );

    println!("\n=== Memory Usage After ===");
    println!("Used Memory:  {:.2} GiB\n", used_mem_after_gib);

    // Optional: show a few sample passwords
    for i in 0..5.min(NUM_PASSWORDS) {
        println!("Password[{}] = {:02x?}", i, passwords[i]);
    }
}
