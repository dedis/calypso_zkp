### Smart Contract Example

Calypso [1] offers a mean to store secrets on the blockchain.
It uses a distributed keypair, where anyone can fetch and use the public key to
encrypt a secret, but the private key is owned by the group of participating nodes.
An encrypted secret is only revealed to the owner, or someone the owner authorized.
When Alice wants to store her secret, she encrypts it with the distributed
public key and stores it by executing a smart contract.

Upon execution, the smart contract storing the encrypted secret must check that
Alice knows the secret, based solely on the encrypted secret it receives.
Otherwise, an adversary Eve could perform a replay attack by copying over the
ciphertext and faking a new access control policy.

For more information, please refer to the appendix of
https://eprint.iacr.org/2018/209.pdf, the sections on Write Transaction Protocol
for Long Term Secrets and D.1 Replay attack.

Go implementation is available at: https://github.com/dedis/cothority/blob/b80515bba800ad738ff79686bd2abfd2822e77d1/calypso/struct.go#L73

### Usage

Create a `Write` instance by executing

```bash
$ make
$ ./create_write
```

This will save the `Write` struct in `write.dat` in the current working directory
and output the value of `LTSID`, distributed public key (`X`) and `write_policy`
used.

Next, try to validate the proof that the write instance is for the given `write_policy`
by editing the hex string in the call to `sodium_hex2bin` in check_proof.c, line 133.

Compile the program again and run check_proof

```bash
$ make
$ ./check_proof
...

proof valid
```

Try forging the hex to something else and run check_proof again

```bash
$ make
$ ./check_proof
...

proof invalid
```

### Dependencies

* Libsodium 1.0.18-stable
