# ShrouDB Veil

**Blind index engine for encrypted search.**

## For Everyone

Veil lets you search encrypted data without decrypting it. When your application stores sensitive information — names, emails, medical records — you need to search it without exposing the raw data. Veil creates searchable "blind tokens" from your data using HMAC-SHA256, so searches compare tokens, never plaintext. The index keys never leave the server.

## For Technical Leaders

Veil is one of ShrouDB's security engines. It solves the encrypted search problem: how do you find records when the data at rest is encrypted?

**The approach:** HMAC-based blind indexing. Plaintext is tokenized (words + character trigrams), each token is HMAC'd with a per-index key, and the resulting blind tokens are stored. To search, the query is tokenized and HMAC'd with the same key, then compared against stored tokens. No decryption occurs during search.

**Four search modes:**
- **Exact** — all query words must appear in the entry
- **Contains** — any query word appears, scored by overlap
- **Prefix** — trigram-based, captures leading-character similarity
- **Fuzzy** — trigram-based with lower threshold, captures edit-distance similarity

**Integration:** Veil is consumed by Sigil (ShrouDB's identity engine) for searchable encrypted fields. When a user record has `pii: true` and `searchable: true` annotations, Sigil calls Veil to generate blind indexes at write time and search them at query time.

**Architecture:** Generic over the ShrouDB Store trait — runs embedded (in-process) or against a remote ShrouDB server. TCP-only (RESP3 wire protocol). No HTTP surface — Veil is machine-to-machine infrastructure.

**Deployment:** Standalone TCP server, embedded in Moat (ShrouDB's single-binary hub), or as a library in other engines via the VeilOps capability trait.
