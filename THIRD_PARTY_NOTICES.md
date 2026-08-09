# Third-party notices

This file records material notices for third-party software distributed as part
of RustyAuth. The generated `THIRD_PARTY_LICENSES.html` file contains the
complete dependency-to-licence inventory and licence texts resolved from the
locked Rust dependency graph.

## SableDB

Source: <https://github.com/sabledb-io/sabledb>

Pinned revision: `8bebc4a60dee404e95608b40ec5c58799e7fa820`

SableDB is built into a separate container image. The following text is copied
verbatim from the `LICENSE` file at the pinned upstream revision:

> Copyright 2024, sabledb.database@gmail.com, all rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
>
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
>
> 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

No SableDB name or contributor name may be used to suggest that SableDB or its
contributors sponsor, endorse, or are affiliated with RustyAuth without
specific prior written permission.

## WebAuthn crates

RustyAuth uses the following Mozilla Public License 2.0 crates without local
source modifications:

- `base64urlsafedata` 0.5.5
- `webauthn-attestation-ca` 0.5.5
- `webauthn-rs` 0.5.5
- `webauthn-rs-core` 0.5.5
- `webauthn-rs-proto` 0.5.5

Their Source Code Form is available from their package pages on
<https://crates.io/> and from <https://github.com/kanidm/webauthn-rs> under
MPL-2.0. RustyAuth's use of those crates does not change the Apache-2.0 licence
of RustyAuth's own source files.

## Other Rust dependencies

RustyAuth's locked dependency graph includes Apache-2.0, MIT, BSD, ISC,
Unicode-3.0, Zlib, BSL-1.0, CDLA-Permissive-2.0, CC0, 0BSD and compatible multi-licence expressions.
Exact package versions, selected licence expressions, upstream links and full
texts are recorded in `Cargo.lock` and `THIRD_PARTY_LICENSES.html`.

Regenerate the inventory after any dependency change:

```sh
cargo about generate --locked --output-file THIRD_PARTY_LICENSES.html about.hbs
```
