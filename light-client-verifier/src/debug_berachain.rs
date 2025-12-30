#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use blst::min_pk::{PublicKey, Signature, AggregateSignature};
    use blst::BLST_ERROR;
    use std::println;
    use sha2::{Sha256, Digest};
    use sha3::{Keccak256, Digest as KeccakDigest};
    use std::convert::TryInto;

    fn to_varint(mut n: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let mut b = (n & 0x7F) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            buf.push(b);
            if n == 0 {
                break;
            }
        }
        buf
    }

    #[test]
    fn debug_berachain_bls_signature() {
        println!("\n--- BERACHAIN FINAL DIAGNOSTICS ---");

        let msg_bytes_original: Vec<u8> = vec![
            115, 8, 2, 17, 229, 225, 224, 0, 0, 0, 0, 0, 34, 72, 10, 32, 131, 176, 172, 147, 254,
            140, 200, 203, 1, 173, 120, 169, 182, 20, 44, 134, 5, 17, 229, 97, 34, 149, 9, 159,
            201, 25, 23, 142, 91, 74, 26, 153, 18, 36, 8, 1, 18, 32, 158, 231, 49, 42, 125, 223,
            9, 108, 240, 234, 27, 126, 95, 125, 96, 184, 147, 94, 192, 154, 215, 193, 197, 62,
            129, 234, 204, 250, 80, 224, 149, 116, 42, 6, 8, 135, 131, 170, 202, 6, 50, 20, 109,
            97, 105, 110, 110, 101, 116, 45, 98, 101, 97, 99, 111, 110, 45, 56, 48, 48, 57, 52
        ];

        let pk_bytes: [u8; 96] = [
            12, 202, 186, 16, 189, 220, 51, 164, 248, 210, 172, 221, 120, 89, 56, 121, 168, 76,
            116, 102, 246, 65, 241, 217, 180, 35, 139, 32, 238, 45, 7, 6, 137, 75, 62, 85, 176,
            116, 64, 152, 197, 11, 155, 72, 33, 218, 50, 7, 9, 99, 237, 85, 165, 143, 21, 64,
            9, 76, 105, 137, 45, 6, 91, 76, 66, 218, 254, 94, 0, 89, 177, 171, 48, 179, 170,
            155, 232, 46, 99, 67, 187, 36, 226, 180, 67, 91, 138, 217, 95, 248, 99, 31, 171,
            54, 166, 231
        ];

        let sig_bytes: [u8; 96] = [
            133, 174, 146, 195, 98, 79, 181, 107, 227, 115, 45, 161, 231, 104, 34, 31, 250, 43,
            184, 142, 245, 174, 213, 239, 127, 109, 37, 200, 11, 63, 254, 24, 83, 115, 222, 144,
            131, 133, 188, 102, 210, 164, 197, 144, 165, 239, 247, 54, 1, 176, 90, 113, 236, 119,
            65, 225, 229, 128, 254, 254, 225, 40, 134, 144, 122, 15, 186, 152, 4, 161, 161, 104,
            108, 60, 193, 25, 213, 68, 185, 65, 65, 203, 78, 166, 145, 132, 70, 190, 1, 164, 72,
            90, 232, 177, 123, 237
        ];

        let pk = PublicKey::from_bytes(&pk_bytes).expect("Failed to parse Public Key");
        let sig = Signature::from_bytes(&sig_bytes).expect("Failed to parse Signature");
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        let rpc_seconds: u64 = 1766576903;
        let rpc_nanos: u64 = 713691052;
        let log_seconds: u64 = 1766490503;

        let header_part = &msg_bytes_original[1..86];
        let footer_part = &msg_bytes_original[94..];

        let create_patched_msg = |secs: u64, nanos: u64, use_prefix: bool| -> Vec<u8> {
            let mut content = Vec::new();

            content.push(0x08);
            content.extend(to_varint(secs));

            if nanos > 0 {
                content.push(0x10);
                content.extend(to_varint(nanos));
            }

            let mut msg = Vec::new();
            msg.extend_from_slice(header_part);

            msg.push(42);
            msg.push(content.len() as u8);
            msg.extend(content);

            msg.extend_from_slice(footer_part);

            if use_prefix {
                let mut final_msg = Vec::new();
                final_msg.push(msg.len() as u8);
                final_msg.extend(msg);
                final_msg
            } else {
                msg
            }
        };

        let variants = vec![
            ("Case A: Original Log Bytes", msg_bytes_original.clone()),
            ("Case B: RPC Secs + RPC Nanos (With Prefix)", create_patched_msg(rpc_seconds, rpc_nanos, true)),
            ("Case C: RPC Secs + RPC Nanos (No Prefix)", create_patched_msg(rpc_seconds, rpc_nanos, false)),
            ("Case D: Log Secs + RPC Nanos", create_patched_msg(log_seconds, rpc_nanos, true)),
        ];

        println!("Testing {} variants...", variants.len());

        for (desc, msg) in variants {
            let res = sig.verify(false, &msg, dst.as_bytes(), &[], &pk, false);
            if res == BLST_ERROR::BLST_SUCCESS {
                println!("✅ SUCCESS: Verified with '{}'!", desc);
                return;
            } else {
                println!("❌ Failed: {}", desc);
            }
        }

        panic!("All variants failed.");
    }
}