# Independent SV2 interoperability tests

This separate host workspace runs DCENT_OS's production `StratumV2Client` against the official [SRI libraries](https://github.com/stratum-mining/stratum/tree/d3a05cfa8b51c6923df81f42bdac7f76b2147830), pinned to `d3a05cfa8b51c6923df81f42bdac7f76b2147830`. SRI constructs and verifies Noise, frames and binary messages; the peer does not use DCENT_OS's mock server, frame builder or certificate signer.

```sh
cd DCENT_OS_Antminer/tools/sv2-interop
cargo +1.90.0 test --locked
```

The four tests exercise a pinned authority, incorrect authority, expired certificate, authenticated transport and replay rejection; fragmented TCP handshakes and frames; standard and extended channel negotiation; parked future jobs and prevhash activation; independently calculated coinbase merkle roots; submit fields and channel flags; accepted/rejected replies and replacement jobs. Every async lifecycle has a 15-second deadline and an abort-on-drop client task. Only loopback sockets are opened. Tests run on every PR and weekly through the `dcentos-sv2-interop` CI workflow.

This harness discovered and now guards three production bugs: certificate verification hashed 64 wire bytes instead of the decoded 32-byte x-only static key; a single TCP read could truncate the handshake; and channel-specific submissions omitted bit 15 of the extension header. The certificate correction follows [SV2 protocol security, section 4.3.1.1](https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md#4311-ec-point-encoding-remarks). The exact handshake read also applies to the JD transport.

The harness has its own lockfile, initially aligned with production versions for shared dependencies. None of the SRI crates is a production dependency. The dependency-age gate accepts only this exact reviewed Git source; changed registry versions still require seven days and matching checksums. Refresh the pin and lock deliberately, review API/wire changes, and rerun both this suite and the ordinary Stratum tests.

This is independent library interoperability evidence, not a full SRI pool/Bitcoin Core regtest deployment, real proof-of-work validation, live accepted-share evidence, or proof of JD mining support. Industrial hardware admission and the project's SV2 bench limits remain in force.

D-Central Technologies: [docs and recovery](https://d-central.tech) · [Fund / Donate / Support](https://d-central.tech/fund/).
