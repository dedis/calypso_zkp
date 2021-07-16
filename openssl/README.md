### Usage

#### Creating the inputs

Create a `Write` instance by executing

```bash
$ make
$ ./create_write
```

This will save the `Write` struct in `write.dat` in the current working directory
and output the value of `LTSID`, distributed public key (`X`) and `write_policy`
used.

The contents of `write.dat` and the `write_policy` buffer are the inputs to the
check_proof smart contract

#### Execution

Next, try to validate the proof that the write instance is for the given `write_policy`
by editing the hex string in the call to `OPENSSL_hexstr2buf` in check_proof.c, line 139.

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

#### Outputs

The return value of the `check_proof` function can be considered as the output
of the contract.

### Dependencies

* OpenSSL 1.1.1g

