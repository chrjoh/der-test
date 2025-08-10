# DER-Test

project to investigate how DER encoding works

## Example running the code

```bash

cargo run              # runs `data` by default
cargo run -- crl       # runs CRL test
cargo run -- cert      # runs cert test
cargo run -- file --path ./fixtures/leaf_cert.der
```
