#  Symbolic Execution of Security Protocol Implementations: Handling Cryptographic Primitives

This repository contains some of the code used in our [USENIX WOOT paper](https://papers.mathyvanhoef.com/woot2018.pdf). It's proof-of-concept code, so reusing the patches will require expertise.

Overview of released code:
- klee: patch to track relationships between symbolic variables
- iwd: symbolic execution of the 4-way handshake
- wpasupp-oracle: proof-of-concept of the decryption oracle in wpa_supplicant
