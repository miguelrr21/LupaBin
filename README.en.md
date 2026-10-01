# LupaBin

*By [Miguel Ángel Rodríguez Romero](https://github.com/miguelrr21).*

**A static-analysis tutor for Windows executables.** LupaBin reads a PE file without ever running it, says what its bytes contain, and explains every statement: which evidence it cites, what it does *not* prove, and where to read more. It is not an antivirus and gives no verdicts.

The didactic report, the glossary and the web interface are in Spanish (the structure supports other languages; translations are welcome). This page is an English overview; the full documentation is in [README.md](README.md).

## What it does

- **Facts from the bytes** (contract 0.12.0), produced in an isolated Docker worker with no network: hashes, PE headers and sections, entropy, imports and exports, structural anomalies, toolchain markers (Microsoft linker Rich header, GCC and MinGW-w64, Go, .NET and PyInstaller), strings, matches of LupaBin's own YARA rules, and bounded static decoding (Base64, hex, repeating-key XOR anchored on known text).
- **What the code calls.** A recursive-descent walk of x86/x64 code (capstone, inside the worker) finds which imported functions are called and from where, and the constant arguments of 72 Windows API functions (registry keys, service names, command lines, URLs, memory protections…). The host re-checks every call and argument against the sample's bytes, without a disassembler of its own.
- **Where main is.** For programs that start through msvcrt.dll's `__getmainargs` (MinGW-w64 against msvcrt, and many of Windows' own), the call where the compiler's startup hands control to `main`, and which calls are reachable from `main` and which only from the startup.
- **Capabilities.** Calls and arguments become sentences such as "the code contains 1 call of this kind: write a value in an autostart (Run) key", with the MITRE ATT&CK technique **only** where the mechanism matches its definition, and how often the capability appears in 3,090 measured benign binaries.
- **Explanations you can verify.** Every sentence is regenerated from the evidence it cites before it is shown; an altered sentence is dropped and counted.
- **UPX 5 packed programs.** The packed block is decompressed without running anything, checked against both Adler-32 sums its header declares, and repeated by the host: the report shows the original sections, entry point and the functions the UPX loader resolves. The unpacked code itself is not analysed yet.
- **VirusTotal, kept apart.** Optional lookup by SHA-256, and upload if VirusTotal does not know the file, shown as an external source and never mixed with LupaBin's facts.

LupaBin favours **the lowest error rate over coverage**. Its extraction and inference methods were measured on benign binaries before being adopted, including the variants that were rejected, and those measurements are written up in [docs/metodo.md](docs/metodo.md) (in Spanish).

## Quick start

Requirements: Python 3.12, [uv](https://docs.astral.sh/uv/) and a Linux Docker engine.

```text
docker build --load -f docker/Dockerfile -t lupabin-worker:0.12.0 .
uv run --frozen lupabin analyze path/to/file.exe --no-virustotal
```

Synthetic, harmless practice files (never execute them):

```text
uv run python -m tests.fixtures.pe_builder --scenario capability-demo --output samples/capability-demo.bin
uv run --frozen lupabin analyze samples/capability-demo.bin --no-virustotal
```

## Web interface

```text
uv sync --extra web
uv run lupabin-web          # http://127.0.0.1:8080
```

To deploy it on a server (Ubuntu 24.04/22.04 or Debian 12, x86_64 or ARM64, e.g. Oracle Cloud Free Tier or Hetzner), follow [docs/deploy.md](docs/deploy.md) (in Spanish). Use a dedicated server: the service controls Docker.

## Ghidra export

After an analysis, the web page offers **Exportar a Ghidra (ZIP)**; from the CLI, run `uv run lupabin export-ghidra report.json --sample file.exe --output evidence.zip`. The ZIP holds the full fact report as JSON and a fixed Java script, `ImportLupaBin.java`, to run from Ghidra's Script Manager (tested with Ghidra 12.1.3 and Java 21). The script refuses a program whose SHA-256 differs from the report's, saves a review file listing every annotation and every piece of evidence it cannot place, and only after you confirm adds comments and `Note` bookmarks. It never removes your own annotations, a second import adds nothing, and a failure or cancellation leaves the program unchanged.

## Self-graded practice

In the web report, **Practicar con este informe** opens up to seven multiple-choice questions about that report (PE structure, imports versus calls, literal and decoded strings, incomplete coverage), each graded with its explanation and the evidence behind it. From the CLI, `uv run --frozen lupabin challenge report.json --practice` asks in the terminal, and `--json` gives an `answers_template` to fill in and grade with `--answers`. Grading is always recomputed from the report. It is practice, not a cheat-proof exam, and the score is about your answers, never about the sample's risk.

## Safety

Samples are never executed or emulated. Parsers run in a container with no network, a read-only root, no capabilities and resource limits; the host validates everything it receives. Only synthetic, harmless fixtures live in this repository: please do not submit real malware. See [SECURITY.md](SECURITY.md).

## Contributing and licence

See [CONTRIBUTING.md](CONTRIBUTING.md) (in Spanish; issues and pull requests in English are welcome). Created by Miguel Ángel Rodríguez Romero and licensed under the [Apache License 2.0](LICENSE): you may use, modify, fork and sell it, as long as you keep the [NOTICE](NOTICE) file and credit the author ("Based on LupaBin, by Miguel Ángel Rodríguez Romero"). The LupaBin name and logo are reserved ([TRADEMARKS.md](TRADEMARKS.md)); contributions require accepting the [CLA](CLA.md).
