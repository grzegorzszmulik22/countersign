Upstream excerpt: RFC 6962 §2.1 (tree hashing + proof generation) and
RFC 9162 §2.1.3.2/§2.1.4.2 (verification pseudocode; 9162 obsoletes 6962, same
tree construction).
Sources: https://www.rfc-editor.org/rfc/rfc6962.txt,
         https://www.rfc-editor.org/rfc/rfc9162.txt
Fetched 2026-11-14. Used for: spec 03 §3 hashes, §6 proofs; V7 of §10.

RFC 6962:
  MTH({}) = SHA-256()
  MTH({d(0)}) = SHA-256(0x00 || d(0))
  MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
              k = largest power of two smaller than n (k < n <= 2k)
  PATH(0, {d(0)}) = {}
  PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])   for m < k
  PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k]) for m >= k

RFC 9162 §2.1.3.2 verifying an inclusion proof (leaf_index, tree_size,
root_hash, inclusion_path):
  1. fail if leaf_index >= tree_size
  2. fn = leaf_index; sn = tree_size - 1
  3. r = leaf hash
  4. for each p in path:
       a. if sn == 0: fail
       b. if LSB(fn) set or fn == sn:
            r = HASH(0x01 || p || r)
            if LSB(fn) not set: right-shift fn and sn equally until
               LSB(fn) set or fn == 0
          else:
            r = HASH(0x01 || r || p)
       c. right-shift fn and sn one time
  5. pass iff sn == 0 and r == root_hash

Published MTH values (third-party implementations; identical construction):
  MTH({})            = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  MTH({""})          = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
  MTH({"L123456"})   = 395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56
  SHA-256(0x01||"N123"||"N456")
                     = aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb
Source of the published values: github.com/crpt/go-merkle rfc6962_test.go
(tests taken from github.com/google/trillian merkle/rfc6962).
