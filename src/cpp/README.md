## Introduction
`otls` provides primitive building blocks for zkTLS or Web Proofs with the [garble-then-prove](https://eprint.iacr.org/2023/964) method and [QuickSilver](https://eprint.iacr.org/2021/076). The current implementation includes the `MPC Model` and `Proxy Model`.

### MPC Model
This is exactly the implementation of the garble-then-prove paper. More specifically, the client runs a 2PC (Garbled Circuit) protocol with the attestor in HandShake and AEAD encryption. In the Post Record phase, the client runs QuickSilver with the attestor to prove the integrity. 

### Proxy Model
In the Proxy-TLS approach, the attestor acts as a proxy between the client and server, forwarding all TLS transcripts. The attestor can record both the Handshake transcripts and the ciphertexts exchanged between the client and server. At the end of the protocol, the client will prove to the attestor with QuickSilver about the validity of the ciphertexts.

In this case, the client proves the key in the AES encryption is derived (the KDF function) from the pms and the messages are encrypted with the same key under the ciphertext recorded by attestor.

### Supported Version
- TLS 1.2
- Cipher suite: AES-GCM

## Installation
### Install Primus-Emp
`otls` is dependent on `primus-emp`.
```bash
git clone https://github.com/primus-labs/primus-emp.git
cd primus-emp

# Building
bash ./compile.sh

```

### Install OTLS
```bash
git clone https://github.com/primus-labs/otls.git
cd otls

# Building
bash ./compile.sh
```


## Test
All the test cases are located in the directory `test`.

* If you want to test the code in local machine, type

   `./run ./bin/[binaries] 12345 [more opts]`
* IF you want to test the code over two machine, type

  `./bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP addresses are hardcoded in the test files.

* An example should run as 
    `./bin/example 1 12345 123 & ./bin/example 2 12345 124`
    
    because different parties need different numbers

## Acknowledgment
This repository is provided as a free resource for the community. You are welcome to use, modify, and distribute the code in accordance with the repository’s license. However, if you use this project in your own work, we ask that you acknowledge us by providing appropriate credit.