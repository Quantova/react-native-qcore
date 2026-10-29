// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quantova_qcore::*;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() as usize) % (max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }

    fn text(&mut self, max: usize) -> String {
        const ALPHABET: &[char] = &[
            'a', 'q', 't', 'v', 'Q', 'T', 'V', '0', '1', '9', 'f', ' ', '-', '_', ':', '/', '.',
            '\u{0}', '\u{e9}', '\u{200b}', '\u{0436}',
        ];
        let n = (self.next() as usize) % (max + 1);
        (0..n)
            .map(|_| ALPHABET[(self.next() as usize) % ALPHABET.len()])
            .collect()
    }

    fn hex(&mut self, max: usize) -> String {
        self.bytes(max).iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[test]
#[ignore = "long running, run with --ignored"]
fn parsing_entry_points_never_panic() {
    let iterations: u64 = std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let mut rng = Rng(std::env::var("FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1));
    for i in 0..iterations {
        match i % 9 {
            0 => {
                let _ = seed_from_mnemonic(rng.bytes(400));
            }
            1 => {
                let _ = valid_address(rng.text(80));
            }
            2 => {
                let _ = same_address(rng.text(80), rng.text(80));
            }
            3 => {
                let known = (0..rng.next() % 4).map(|_| rng.text(60)).collect();
                let _ = lookalike_of(rng.text(60), known);
            }
            4 => {
                let _ = chain_id_from_name(rng.text(40));
            }
            5 => {
                let _ = check_endpoint(rng.text(80));
            }
            6 => {
                let _ = map_slot_key(rng.next(), rng.hex(48));
            }
            7 => {
                let _ = map_addr_word_key(rng.next(), rng.hex(48), rng.next());
            }
            _ => {
                let _ = mnemonic_from_seed(rng.bytes(80));
            }
        }
    }
}
