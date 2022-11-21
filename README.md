# CAEAD
Experimental implementations of committing AEADs for research purposes.

This repository contains implementations of the following committment schemes:

- CTX, by John Chan & Phillip Rogaway [1]
- UtC with CX[E], by Mihir Bellare and Viet Tung Hoang [2]
- HtE, by Mihir Bellare and Viet Tung Hoang [2]

These committment schemes are built upon:
- ChaCha20-Poly1305
- BLAKE2b


Credits to CX[E] implementation by [Michael Rosenberg](https://github.com/rozbb/kc-aeads) which provided inspiration.

[1]: Chan, John., Rogaway, Phillip., 2022, "On Committing Authenticated Encryption", https://eprint.iacr.org/2022/1260
[2]: Bellare, Mihir., Hoang, Viet Tung., 2022, "Efficient Schemes for Committing Authenticated Encryption", https://eprint.iacr.org/2022/268