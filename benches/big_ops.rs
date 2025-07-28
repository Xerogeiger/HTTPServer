use criterion::{criterion_group, criterion_main, Criterion};
use HTTPServer::ssl::bigint::BigUint;
use HTTPServer::ssl::aes::AesCipher;
use HTTPServer::ssl::record::{decrypt_record, encrypt_record, RecordHeader, TLS_VERSION_1_2, MacAlgorithm};

fn bench_big_operations() {
    let a = BigUint::from_bytes_be(&[0xFF; 128]);
    let b = BigUint::from_bytes_be(&[0xEE; 128]);
    let loops = 100u64;

    let start = std::time::Instant::now();
    for _ in 0..loops {
        a.add(&b);
    }
    let add_ns = start.elapsed().as_nanos() / loops as u128;

    let start = std::time::Instant::now();
    for _ in 0..loops {
        a.sub(&b);
    }
    let sub_ns = start.elapsed().as_nanos() / loops as u128;

    let start = std::time::Instant::now();
    for _ in 0..loops {
        a.mul(&b);
    }
    let mul_ns = start.elapsed().as_nanos() / loops as u128;

    let start = std::time::Instant::now();
    for _ in 0..loops {
        a.div_rem_u32(3);
    }
    let div_ns = start.elapsed().as_nanos() / loops as u128;

    let start = std::time::Instant::now();
    for _ in 0..loops {
        a.to_bytes_be();
    }
    let to_bytes_ns = start.elapsed().as_nanos() / loops as u128;

    println!(
        "add {} ns, sub {} ns, mul {} ns, div {} ns, bytes {} ns",
        add_ns, sub_ns, mul_ns, div_ns, to_bytes_ns
    );

    let cipher = AesCipher::new_128(&[0u8; 16]);
    let mac_key = b"bench-key".to_vec();
    let payload = vec![0xAAu8; 512];

    let start = std::time::Instant::now();
    for i in 0..loops {
        let _ = encrypt_record(23, &payload, &cipher, &mac_key, i as u64, MacAlgorithm::Sha256);
    }
    let enc_ns = start.elapsed().as_nanos() / loops as u128;

    let record = encrypt_record(23, &payload, &cipher, &mac_key, 0, MacAlgorithm::Sha256);
    let header = RecordHeader::parse(&record[..5]).unwrap();
    let body = &record[5..];

    let start = std::time::Instant::now();
    for i in 0..loops {
        let _ = decrypt_record(&header, body, &cipher, &mac_key, i as u64, MacAlgorithm::Sha256);
    }
    let dec_ns = start.elapsed().as_nanos() / loops as u128;

    println!("enc {} ns, dec {} ns", enc_ns, dec_ns);
}

fn criterion_benchmark(_c: &mut Criterion) {
    bench_big_operations();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
