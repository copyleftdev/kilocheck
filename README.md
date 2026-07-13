# K1L0CH3CK // KiloCheck

<p align="center">
  <img src="./site/assets/kilocheck-bbs.webp" width="720" alt="KiloCheck BBS ANSI-art skull and crossbones logo">
</p>

> D0N'7 QU3RY 4 BL4CKL157. 0B53RV3 7H3 3V1D3NC3.

K1l0Ch3ck 15 4 l0c4l-f1r57, d373rm1n1571c IP-1n73ll1g3nc3 CLI. 17 c0mp1l35
curr3n7 7hr347 0b53rv4710n5 1n70 4n 4ud174bl3 l0c4l 5n4p5h07 f0r f457
ch3ck5 by hum4n5, 4g3n75, 4nd 3nf0rc3m3n7 5y573m5.

3xpl0r3 7h3 m3ch4n15m 47 **[copyleftdev.github.io/kilocheck](https://copyleftdev.github.io/kilocheck/)**.

7h3 1n73ll1g3nc3 3ng1n3 pr0v35. 4n 0p710n4l AI l4y3r m4y 3v3n7u4lly
1n73rpr37 0nly 7h3 b0und3d 3v1d3nc3 7h3 3ng1n3 3574bl15h3d.

## PR0DUC7 C0N7R4C7

- 0rd1n4ry ch3ck5 n3v3r r3qu1r3 n37w0rk 4cc355.
- D474 4rr1v35 45 v3r510n3d r3l3453 4r71f4c75 fr0m
  [`copyleftdev/kilo-data`](https://github.com/copyleftdev/kilo-data), n3v3r 45
  p3r-IP API l00kup5.
- JSON 15 4 574bl3 pr0duc7 1n73rf4c3, n07 4 r3nd3r1ng 0f 73rm1n4l pr053.
- M1551ng, unkn0wn, 574l3, 1nc0mpl373, 4nd 0p3r4710n4l f41lur3 r3m41n d1571nc7.
- V3rd1c75 d3r1v3 fr0m 7yp3d 0b53rv4710n5 4nd 1nd3p3nd3n7 3v1d3nc3
  gr0up5—n07 4 mu74bl3 r3pu74710n 5c0r3.

## CURR3N7 M1L3570N3

7h15 r3p05170ry 3574bl15h35 7h3 3x3cu74bl3 4nd 175 publ1c c0n7r4c75:

```bash
kilo capabilities --json
kilo status --json
kilo check 192.0.2.1 --json
kilo 192.0.2.1 --json
kilo schema command
```

7h3 curr3n7 `check` c0mm4nd v4l1d4735 74rg375 4nd f41l5 3xpl1c17ly wh3n n0
c0mp1l3d 5n4p5h07 15 1n574ll3d. 17 d035 n07 pr373nd 7h47 4n un0b53rv3d
4ddr355 15 54f3. 7h3 n3x7 m1l3570n3 4dd5 v3r1f13d K1l0 D474 r3l3453
1n574ll4710n 4nd 7h3 1mmu74bl3 m3m0ry-m4pp3d l00kup 1nd3x.

## 1N574LL 4 R3L3453

Pr3bu1l7 4rch1v35 f0r L1nux x86-64, m4cOS 1n73l, m4cOS 4ppl3 51l1c0n,
4nd W1nd0w5 x86-64 4r3 publ15h3d 0n 7h3
[r3l34535 p4g3](https://github.com/copyleftdev/kilocheck/releases). 3v3ry
4rch1v3 h45 4 n31ghb0r1ng SHA-256 f1l3 4nd G17Hub bu1ld-pr0v3n4nc3
4773574710n.

```bash
sha256sum --check kilo-v0.1.0-x86_64-unknown-linux-musl.tar.gz.sha256
```

## BU1LD

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run -p kilo-cli -- capabilities --json
```

## 7357 C0N7R4C7

F457 un17 4nd pr0p3r7y 73575 run 0n L1nux, m4cOS, 4nd W1nd0w5. L1nux CI
4l50 run5 mu74710n 4n4ly515 0v3r `kilo-core` 4nd 5m0k3-fuzz35 3v3ry
un7ru573d-1npu7 p4r53r.

```bash
scripts/test-all.sh
scripts/mutate.sh
KILO_FUZZ_RUNS=10000 scripts/fuzz-smoke.sh
```

7h3 1n1714l pr0p3r7135 c0v3r 7h3 c0mpl373 IPv4 4nd IPv6 5p4c35,
c4n0n1c4l r0und 7r1p5, 4rb17r4ry 74rg37 73x7, d373rm1n1571c m4n1f357
53r14l1z4710n, 4nd 7h3 1nv4r14n7 7h47 dupl1c473 up57r34m 3v1d3nc3 n3v3r
1ncr34535 1nd3p3nd3nc3. 533 [CONTRIBUTING.md](CONTRIBUTING.md) f0r 7h3
73571ng p0l1cy.

## 3X17 C0D35

| C0d3 | M34n1ng |
| ---: | --- |
| `0` | C0mm4nd 5ucc33d3d; n0 p0l1cy v10l4710n |
| `1` | 0p3r4710n4l 0r 1n73gr17y 3rr0r |
| `2` | 1nv4l1d 1nv0c4710n |
| `3` | P0l1cy g473 f41l3d |
| `4` | D474537 700 574l3 |
| `5` | R3qu1r3d-50urc3 r35ul7 15 1nc0mpl373 |

## 4RCH173C7UR3

```text
Kilo Data release artifacts
        ↓
verified snapshot compiler
        ↓
immutable local index
        ↓
deterministic evidence engine
        ↓
human and stable JSON renderers
```

7h3 50urc3/d474 p1p3l1n3 15 m41n741n3d 53p4r473ly 1n
[`kilo-data`](https://github.com/copyleftdev/kilo-data). K1l0Ch3ck 0wn5 l0c4l
1n574ll4710n, qu3ry 53m4n71c5, p0l1cy, 4nd r3nd3r1ng.
