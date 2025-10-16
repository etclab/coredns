# etcd_crypto: RSA to AES Migration TODO

## Context
See `@~/Projects/calypso/ztrust-dns/etcd-client/rsa-aes.md` for full rationale.

**Goal**: Remove RSA-OAEP (serves no research purpose), make AES-256-GCM the type `01` baseline (Approach 2: Enclave).

## Current Status: Partially Migrated

### Completed ✅
- `rsa.go` deleted
- All RSA encryption/decryption logic removed from `crypto.go`
- `calypso.go` deleted
- `wkdibe.go` deleted

### Remaining Work ❌

#### 1. Code Changes
**File**: `plugin/etcd_crypto/crypto.go`
- [ ] Line 15: Change `TypeMarkerAES = "04"` → `"01"`
- [ ] Update comment: `const TypeMarkerAES = "01" // AES-256-GCM encryption (Approach 2: Enclave)`

#### 2. Documentation: README.md
**Type code references** (change 04 → 01):
- [ ] Line 14: `type marker (0x04)` → `(0x01)`
- [ ] Line 26: `"04:BASE64_CIPHERTEXT"` → `"01:BASE64_CIPHERTEXT"`
- [ ] Line 35: `04 = AES-256-GCM` → `01 = AES-256-GCM`

**Remove RSA references**:
- [ ] Lines 137-143: Delete entire "Storage Format Details" type table section OR rewrite to show only:
  ```
  - `01` = AES-256-GCM encryption (Approach 2: Enclave)
  - `02` = WKD-IBE encryption (Approach 3)
  - `03` = Calypso encryption (Approach 4)
  - No marker = Plaintext (Approach 0)
  ```
- [ ] Line 163: Remove RSA from performance comparison text

**Add migration note**:
- [ ] Add note explaining RSA removal: "Note: RSA-OAEP was removed as it served no research purpose and created confusion in comparative evaluations."

#### 3. Testing
- [ ] Verify existing AES tests still pass after type code change
- [ ] Test encrypted record creation with new type `01`
- [ ] Test backward compatibility (if needed): can old `04` records be read?

#### 4. Coordination with etcd-client
**Check if etcd-client needs updates**:
- [ ] Verify etcd-client tool uses same type code constant
- [ ] Update etcd-client if it hardcodes type `04`
- [ ] Ensure etcd-client examples/docs match new type codes

## Migration Impact

**Breaking change**: Type code `04` → `01`
- Acceptable because: research prototype, RSA never used in evaluations
- Existing test data with type `04` can be regenerated
- No production deployments affected

**Research benefits**:
1. Removes confusion from performance comparisons
2. Establishes AES as proper baseline (minimal overhead for encrypted storage)
3. Clear 1:1 mapping: Type 01=Enclave, 02=WKD-IBE, 03=Calypso
4. Simplifies documentation and reduces PKI complexity

## Files Modified (Expected)
```
M plugin/etcd_crypto/crypto.go       (type constant 04→01)
M plugin/etcd_crypto/README.md       (remove RSA, update type codes)
```

## Related Files to Check
- `~/Projects/calypso/ztrust-dns/etcd-client/` - may need type code updates
- Any test fixtures with hardcoded type `04`
- Documentation in parent directories referencing type codes