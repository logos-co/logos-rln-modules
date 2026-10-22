/* rln-signal: the RLN signal binding x = hash_to_field_le(signal).
 *
 * Writes the canonical 32-byte little-endian BN254 field element
 *   x = from_le_bytes_mod_order(keccak256(signal[0..len]))
 * into `out`. Hex-encode those 32 bytes to obtain `signal_hash_hex` for
 * liblogos_rln_module's generate_proof_prehashed / validate_proof_prehashed;
 * the same value is the `share_x` field of every RateLimitProof reply.
 *
 * Returns 0 on success, 1 if `out` is NULL, 2 if `signal` is NULL with a
 * non-zero `len` (NULL with len == 0 hashes the empty message).
 */
#ifndef RLN_SIGNAL_H
#define RLN_SIGNAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t rln_signal_hash(const uint8_t *signal, size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* RLN_SIGNAL_H */
