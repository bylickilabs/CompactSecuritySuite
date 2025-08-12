
# Mathematical Notation – Compact Security Suite - LaTeX

## 1. Hashing

Given a message/file \( m \in \Sigma^* \), algorithm \( a \in \{\mathrm{MD5}, \mathrm{SHA1}, \mathrm{SHA256}, \mathrm{SHA512}\} \):

\[
H_a(m) = \mathrm{hash}_a(m) \in \Sigma^{\ell_a}
\]

Incremental chunk-based hashing:

\[
m = c_1 \| c_2 \| \dots \| c_t,\quad
h_0 = \mathrm{IV}_a,\quad
h_i = \mathrm{Upd}_a(h_{i-1}, c_i),\quad
H_a(m) = \mathrm{Fin}_a(h_t)
\]

Verification:

\[
\mathrm{verify}(m, d, a) := [\,H_a(m) = d\,]
\]

<br>

---

<br>

## 2. Key Derivation (scrypt)

Password \( P \), salt \( S \xleftarrow{\$} \Sigma^{128} \) (16 bytes):

\[
K = \mathrm{scrypt}(P, S; N, r, p, \ell)
\]
App parameters: \( N=2^{15}, r=8, p=1, \ell=32 \) (256-bit AES key).

<br>

---

<br>

## 3. Authenticated Encryption (AES-256-GCM)

Nonce \( N \xleftarrow{\$} \Sigma^{96} \) (12 bytes), optional associated data \( A = \bot \), plaintext \( M \):

\[
(C, T) = \mathrm{GCM\_Enc}_K(N, M, A)
\]
\[
M = \mathrm{GCM\_Dec}_K(N, C, A, T) \quad \text{if Tag valid, else } \bot
\]

<br>

---

<br>

## 4. Container Format (.enc)

Header fields:
- Magic = 'BSEC' (4B)
- Version \( v = 1 \)
- \(|S| = 16\), \(|N| = 12\)

Layout:

\[
\mathrm{enc\_file} = \underbrace{\mathrm{BSEC}}_{\text{Magic}} \| v \| |S| \| |N| \| S \| N \| C \| T
\]

Where:
\[
K = \mathrm{scrypt}(P, S; 2^{15}, 8, 1, 32), \quad (C, T) = \mathrm{GCM\_Enc}_K(N, M, \bot)
\]

Decryption/validation:
1. Parse header, extract \( S, N \)
2. \( K = \mathrm{scrypt}(P, S; \dots) \)
3. \( \tilde M = \mathrm{GCM\_Dec}_K(N, C, \bot, T) \)
4. \( \tilde M = \bot \) → error; else \( M = \tilde M \)

<br>

---

<br>

## 5. Integrity & Authenticity

- Cryptographic (GCM tag):
\[
\Pr[\mathrm{Forge}] \le \mathrm{negl}(\lambda)
\]
- Non-cryptographic (ZIP/CRC-32):
\[
\mathrm{CRC}_{32}(m) = m(X) \bmod p(X)
\]
(No security, only error detection).

<br>

---

<br>

## 6. Lossless Compression (ZIP/DEFLATE)

Compressor \( Z: \Sigma^* \to \Sigma^* \), decompressor \( Z^{-1} \):
\[
Z^{-1}(Z(m)) = m
\]

Compression ratio:
\[
\rho(m) = \frac{|Z(m)|}{|m|}
\]

Entropy bound (source \( X \) i.i.d.):
\[
\mathbb{E}[\,|Z(m)|\,] \ge n \cdot H(X)
\]

DEFLATE ≈ LZ77 + Huffman coding:
\[
Z(m) = \mathrm{Huff}(\mathrm{LZ77}(m))
\]

<br>

---

<br>

## 7. Secure Deletion (Shred)

For file \( F \) of size \( L \) and pass sequence \(\{p_i\}\):

\[
\mathrm{Overwrite}(F, \{p_i\}) : \forall i:\, \mathrm{write}(F, p_i) \Rightarrow \mathrm{truncate}(F) \Rightarrow \mathrm{unlink}(F)
\]

Types:
- **1-Pass:** \( p_1 = \texttt{0x00} \)
- **DoD 3-Pass:** \( p_1 = \texttt{0x00}, p_2 = \texttt{0xFF}, p_3 \xleftarrow{\$} \Sigma^{8L} \)

**SSD note:** Wear-leveling/TRIM → overwriting not guaranteed.  
**Alternative:** *Crypto-shredding* — encrypt \( M \) with random \( K \), then erase \( K \).

<br>

---

<br>

## 8. End-to-End Flow

Encryption:
\[
S \xleftarrow{\$} \Sigma^{128},\; N \xleftarrow{\$} \Sigma^{96},\;
K = \mathrm{scrypt}(P, S),\;
(C, T) = \mathrm{GCM\_Enc}_K(N, M, \bot)
\]
File:
\[
\mathrm{BSEC} \| 1 \| 16 \| 12 \| S \| N \| C \| T
\]

Hashing:
\[
d = H_{\mathrm{SHA256}}(m)
\]

ZIP:
\[
\mathrm{zip} = Z(\{f_i\}), \quad \forall f_i:\; \mathrm{CRC}_{32}(f_i) \text{ (meta)}
\]

Shred:
\[
\mathrm{DoD}(F) = \mathrm{Overwrite}(F, \{0x00, 0xFF, \$ \})
\]

<br>

---

<br>

## 9. Check Equations

- Hash check: \( H_{\mathrm{SHA256}}(m) \stackrel{?}{=} d \)
- GCM tag check: \( \mathrm{GCM\_Dec}_K(N, C, \bot, T) \neq \bot \)
- ZIP CRC check: \( \mathrm{CRC}_{32}(\hat f_i) \stackrel{?}{=} \mathrm{CRC}_{32}(f_i) \)
- Compression ratio: \( \rho(m) < 1 \) preferred; for random-like data \(\rho \approx 1\).
