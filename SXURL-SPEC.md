
# SXURL (Slice eXact URL): fixed length, sliceable URL identifier

## 1. Intent and why

* **Intent**: turn a URL into a **single 256-bit token** printed as **64 hex characters** where each URL part lives in a fixed hex slice.
* **Why**: fixed size keys are easy to store and index, and hex substring filters are fast. Per-field hashing avoids large dictionaries, yet lets you group or filter by TLD, domain, subdomain, port, path, params, fragment.

## 2. Scope

* **Schemes**: `https`, `http`, `ftp`. Anything else is an error.
* **Hosts**: DNS names only. IP literals are out of scope for this profile.
* **Goal**: indexing and querying. If you need round-trip reconstruction, also store `id → url`.

---

## 3. Normalization

* Lowercase **scheme** and **host**.
* Convert host to ASCII with **IDNA UTS-46**. Validate: each label 1..63 bytes, total host ≤ 255 bytes.
* Split host using your Public Suffix List snapshot:

  * `tld`: the public suffix, can be multi-label.
  * `domain`: registrable label left of `tld`.
  * `sub`: everything left of `domain`, joined with `.`. May be empty.
  * If you do not use PSL, fallback to last label as `tld`.
* **Path**, **query**, **fragment**: treat as raw bytes. Do not rewrite percent encodings or `+`.

---

## 4. Per-field hash

For component bytes $B$ and ASCII label $L$:

$$
H_n(L,B) = \operatorname{lower}_n\Big(\mathrm{SHA256}(L \parallel 0x00 \parallel B)\Big)
$$

Labels: `"tld"`, `"domain"`, `"sub"`, `"path"`, `"params"`, `"frag"`.

---

## 5. Binary layout and hex anatomy

All fields are nibble-aligned for clean slicing. Total is **256 bits = 64 hex characters**.

```
[ header:12 ][ tld_h:16 ][ domain_h:60 ][ sub_h:32 ][ port:16 ]
[ path_h:60 ][ params_h:36 ][ frag_h:24 ]
```

### 5.1 Header, 12 bits at hex slice `[0..3)`

* Bits: `[ver:4][scheme:3][flags:5]`
* `ver`: `0001` for version 1
* `scheme`: only these codes are valid

  * `https = 000`
  * `http  = 001`
  * `ftp   = 010`
* `flags` bits, from MSB to LSB: `sub_present, params_present, frag_present, port_present, reserved(0)`

Header value:

$$
\text{header} = (1 \ll 8)\;|\;(\text{scheme} \ll 5)\;|\;\text{flags}
$$

Examples: https no flags → `0x100`; http params+frag → `0x12C`; ftp sub+port → `0x152`.

### 5.2 Fixed hex slice map

| Slice     | Hex range  | Bits | What it contains                            |
| --------- | ---------- | ---: | ------------------------------------------- |
| header    | `[0..3)`   |   12 | version, scheme, flags                      |
| tld\_h    | `[3..7)`   |   16 | H16 over TLD bytes                          |
| domain\_h | `[7..22)`  |   60 | H60 over registrable domain label           |
| sub\_h    | `[22..30)` |   32 | H32 over full subdomain string with dots    |
| port      | `[30..34)` |   16 | network order port, `0000` if absent        |
| path\_h   | `[34..49)` |   60 | H60 over path bytes, leading slash included |
| params\_h | `[49..58)` |   36 | H36 over raw query string after `?`         |
| frag\_h   | `[58..64)` |   24 | H24 over fragment after `#`                 |


  Bits:    12    16      60        32      16      60       36      24
         ┌────┬─────┬─────────┬────────┬─────┬─────────┬────────┬──────┐
         │hdr │ tld │ domain  │  sub   │port │  path   │ params │ frag │
         └────┴─────┴─────────┴────────┴─────┴─────────┴────────┴──────┘
  Hex:   [0-3)[3-7) [7-22)   [22-30) [30-34)[34-49)  [49-58) [58-64)
---

## 6. Encoding algorithm

**Input**: URL string
**Output**: 32 bytes, printed as 64 hex characters

1. Normalize into `scheme, tld, domain, sub, port, path, query, fragment`.
2. If `scheme ∉ {https, http, ftp}`, return `ERR_INVALID_SCHEME`.
3. Set flags:

   * `sub_present = (sub != "")`
   * `params_present = (query != "")`
   * `frag_present = (fragment != "")`
   * `port_present = (port is provided)`
4. Map scheme to 3 bits: https `000`, http `001`, ftp `010`.
5. Hash variable parts with $H_n$ at their widths.
6. Pack big-endian:

   ```
   header:12, tld_h:16, domain_h:60, sub_h:32,
   port:16, path_h:60, params_h:36, frag_h:24
   ```
7. Emit as 64 hex characters.

Pseudocode

```pseudo
function scheme_bits(s):
  if s=="https": return 0b000
  if s=="http":  return 0b001
  if s=="ftp":   return 0b010
  error(ERR_INVALID_SCHEME)

flags = (sub!=""?1:0)<<4 | (query!=""?1:0)<<3 | (frag!=""?1:0)<<2
       | (port_present?1:0)<<1 | 0

header = (1<<8) | (scheme_bits(scheme)<<5) | flags

tld_h    = H16("tld",    tld)
domain_h = H60("domain", domain)
sub_h    = H32("sub",    sub)
port_u16 = port_present ? port : 0
path_h   = H60("path",   path)
params_h = H36("params", query)
frag_h   = H24("frag",   fragment)

id_bits = concat_be([header,tld_h,domain_h,sub_h,port_u16,path_h,params_h,frag_h],
                    [12,   16,   60,      32,   16,      60,     36,      24])
hex64 = to_hex(id_bits, 64)
```

---

## 7. Decoding and querying

Decoding yields: version, scheme, presence flags, 16-bit port, and each component’s hash slice.

**Equality filter** for a component with a `b`-bit slice:

1. Normalize the probe value the same way.
2. Compute $H_b$ with the same label.
3. Compare to the component’s fixed hex substring.

**False positive rate**

$$
\mathrm{FPR} \approx 2^{-b}
$$

* TLD 16 bit → about 1 in 65,536. Good for coarse TLD buckets.
* Domain 60 bit → negligible in practice.
* Path 60 bit → negligible in practice.
* Params 36 bit → about 1 in $2^{36}$. You already accept collisions here.
* Fragment 24 bit → about 1 in 16,777,216.

**Common substring filters**

* TLD `.ai`: `hex[3..7] == H16("tld",".ai")`.
* Domain `google`: `hex[7..22] == H60("domain","google")`.
* Subdomain `api`: `hex[22..30] == H32("sub","api")`.
* Port 8443: header must show `port_present`, and `hex[30..34] == "20fb"`.
* Path `/search`: `hex[34..49] == H60("path","/search")`.
* Params bucket for a query `Q`: `hex[49..58] == H36("params", Q)`.
* Fragment bucket `modules`: `hex[58..64] == H24("frag","modules")`.

---

## 8. Validation and errors

* Invalid scheme → `ERR_INVALID_SCHEME: only https, http, ftp`.
* Invalid DNS host or IDNA failure → `ERR_HOST_NOT_DNS`.
* Host label not in 1..63 bytes or total host > 255 bytes → `ERR_HOST_LEN`.
* If `port_present=0`, `port` slice must be `0000`.
* If `port_present=1`, port must be 1..65535.
* `ver` must be 1. Reserved header bit must be 0.

---

## 9. Notes on collisions and grouping

* `params_h` and `frag_h` are intended to be **buckets**. Collisions are fine. Combine with domain and path for tighter buckets when needed.
* For exact URL, use a KV: `id_hex64 → url`.

---

## 10. Examples, computed with this spec

### A) https, root

`https://docs.rs/`

* **ID**: `1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356`
* **Slices**

  * header `[0..3)=100`   ver 1, https, no flags
  * tld `[3..7)=2397`     H16("tld","rs")
  * domain `[7..22)=f4018b8efa86c31`  H60("domain","docs")
  * sub `[22..30)=440f00a9`           H32("")
  * port `[30..34)=0000`
  * path `[34..49)=98911d784580332`   H60("/")
  * params `[49..58)=c354b043a`       H36("")
  * frag `[58..64)=29e356`            H24("")

### B) https, search with params

`https://google.com/search?q=hirsh+pithadai&oq=hirsh+pithadai&ie=UTF-8`

* **ID**: `10862fe03e9505795e1d08440f00a90000239f9d65dd897537a7da04b629e356`
* **Slices**

  * header `108`               https, params present
  * tld `62fe`                 H16("tld","com")
  * domain `03e9505795e1d08`   H60("domain","google")
  * sub `440f00a9`
  * port `0000`
  * path `239f9d65dd89753`     H60("/search")
  * params `7a7da04b6`         H36(raw query)
  * frag `29e356`

### C) http, sub present, explicit :80, params and fragment

`http://www.example.com:80/?a=1#f`

* **ID**: `13e62fe9cee73c091a1a7baa4cd029005098911d78458033269b3218b2e78f0f`
* **Slices**

  * header `13e`             http, sub+port+params+frag present
  * tld `62fe`               H16("tld","com")
  * domain `9cee73c091a1a7b`
  * sub `aa4cd029`           H32("www")
  * port `0050`              80
  * path `98911d784580332`   H60("/")
  * params `69b3218b2`       H36("a=1")
  * frag `e78f0f`            H24("f")

### D) http, sub present, explicit :8443, params and fragment

`http://api.example.ai:8443/a/b?x=1#frag`

* **ID**: `13e2e319cee73c091a1a7b5b7f800220fbcb7e8070cf84487f86a9df2b86e801`
* **Slices**

  * header `13e`
  * tld `2e31`               H16("tld","ai")
  * domain `9cee73c091a1a7b`
  * sub `5b7f8002`           H32("api")
  * port `20fb`              8443
  * path `cb7e8070cf84487`   H60("/a/b")
  * params `f86a9df2b`       H36("x=1")
  * frag `86e801`            H24("frag")

### E) ftp, explicit :21, file path

`ftp://ftp.example.org:21/pub/file.txt`

* **ID**: `152daa39cee73c091a1a7b4efc0aa00015b75ba348fb4b4b8c354b043a29e356`
* **Slices**

  * header `152`             ftp, sub+port present
  * tld `daa3`               H16("tld","org")
  * domain `9cee73c091a1a7b`
  * sub `4efc0aa0`           H32("ftp")
  * port `0015`              21
  * path `b75ba348fb4b4b8`   H60("/pub/file.txt")
  * params `c354b043a`
  * frag `29e356`

### F) invalid scheme

`ws://chat.example.net/socket` → `ERR_INVALID_SCHEME: only https, http, ftp`

---

## 11. Query cookbook, substring positions

Assume `id_hex` stores the 64-hex string.

* All `.ai`:

  ```
  WHERE SUBSTR(id_hex, 3+1, 4) = :h_tld_ai   -- hex[3..7)
  ```
* `.com` + domain `google` + path `/search`:

  ```
  WHERE SUBSTR(id_hex, 3+1, 4)  = :h_tld_com     -- [3..7)
    AND SUBSTR(id_hex, 7+1, 15) = :h_domain_g    -- [7..22)
    AND SUBSTR(id_hex,34+1, 15) = :h_path_s      -- [34..49)
  ```
* Port 8443:

  ```
  WHERE SUBSTR(id_hex,30+1,4) = '20fb'          -- [30..34)
  ```
* Params bucket for a probe query `Q`:

  ```
  WHERE SUBSTR(id_hex,49+1,9) = :h_params_Q     -- [49..58)
  ```

---

## 12. Compliance checklist

* [ ] Scheme in `{https, http, ftp}`, else error.
* [ ] Host lowercased, IDNA mapped, label and host lengths valid.
* [ ] PSL split into `sub, domain, tld` or defined fallback.
* [ ] Labeled SHA-256 truncation used for each hashed field.
* [ ] Header `[ver:4][scheme:3][flags:5]`, reserved bit is 0.
* [ ] Big-endian concatenation to 256 bits, printed as 64 hex.
* [ ] Port slice is `0000` when `port_present=0`.
* [ ] Deterministic normalization across runs.

---

## 13. One page encode diagram

```
URL
 ├─ normalize (scheme+host lowercase, IDNA host, PSL split)
 ├─ flags ← presence of sub, params, frag, port
 ├─ scheme → {https=000, http=001, ftp=010}
 ├─ H16(tld), H60(domain), H32(sub), H60(path), H36(params), H24(frag)
 ├─ port_u16 or 0 if absent
 └─ pack big-endian:
     [ header:12 | tld:16 | domain:60 | sub:32 | port:16 | path:60 | params:36 | frag:24 ]
       → 32 bytes → 64 hex
```



