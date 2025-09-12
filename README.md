# BinSight

<<<<<<< HEAD
**BinSight** is a powerful, modular binary analysis tool built for security researchers, reverse engineers, and developers. It currently supports ELF binaries, with *planned* support for PE and Mach-O formats. BinSight offers detailed insights into a binary’s structure, security properties, symbols, and metadata via both TUI and CLI interfaces.

## Features

- **Modular Design** - Add or extend analysis with plug-and-play modules
- **Multi-Format Support** - Analyze ELF now, PE and Mach-O coming soon
- **Export Ready** - Output full analysis as machine-readable JSON
- **TUI Explorer** - Navigate binary internals via ncurses UI (msfconsole-like)
- **CLI Mode** - Run headless for automation, CI, or pipelines
- **Lua Plugin Support** - Script modules dynamically, no recompilation

## Getting Started

### Build Requirements
=======
**BinSight** (or **BS** for short) is a powerful, modular binary analysis tool built for security researchers, reverse engineers, and developers. It currently supports ELF binaries, with *planned* support for PE and Mach-O formats. BinSight offers detailed insights into a binary’s structure, security properties, symbols, and metadata via both TUI and CLI interfaces.

## ✨ Features

- 🧩 **Modular Design** – Add or extend analysis with plug-and-play modules
- 🧠 **Multi-Format Support** – Analyze ELF now, PE and Mach-O coming soon
- 🔐 **Security Insight** – Detect RELRO, NX, PIE, canaries, RWX, etc.
- 🧵 **Debug Awareness** – Check for stripped binaries, DWARF, build IDs
- 🔎 **Symbols & Relocations** – View symbol tables, relocations, sections
- 📤 **Export Ready** – Output full analysis as machine-readable JSON
- 💻 **TUI Explorer** – Navigate binary internals via ncurses UI
- 🛠️ **CLI Mode** – Run headless for automation, CI, or pipelines
- 🧬 **Lua/WASM Plugin Support** – Script modules dynamically, no recompilation

## 📸 Screenshots

> Coming soon...

## 🚀 Getting Started

### 🔧 Build Requirements
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55

- GCC or Clang
- [CMake](https://cmake.org/)
- `ncurses` development headers (`libncurses-dev` or similar)
<<<<<<< HEAD
- `libmagic` development headers (`libmagic` or similar)

### Build
=======

### ⚙️ Build (via Makefile or CMake)
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55

```bash
make            # or use cmake ..
````

### ▶️ Run

```bash
./binsight /path/to/binary
```

<<<<<<< HEAD
## Plugin System
=======
## 🧩 Plugin System
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55

BinSight is built around a modular plugin system. Each plugin defines:

```c
typedef struct {
    const char *name;
    const char *description;
    bool (*supports_format)(BinaryFormat fmt);
    char* (*run)(const BinaryFile *bin);
} Plugin;
```

<<<<<<< HEAD
### Adding a Module
=======
### ➕ Adding a Module
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55

1. Create your plugin source file in `src/modules/<format>/`.
2. Implement the `Plugin` interface.
3. Register it in the module registry (static for now).
4. Rebuild the binary — your plugin will appear in the TUI/CLI interface.

<<<<<<< HEAD
## Directory Structure
=======
## 📂 Directory Structure
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55

```text
bin-analyzer/
├── src/
<<<<<<< HEAD
│   ├── core/                        # Core engine (Arena Allocator, Error handler, Dispatcher...etc)
=======
│   ├── core/                        # Core engine (TUI, CLI, dispatch, export)
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55
│   ├── formats/                     # Format loaders (ELF, PE, etc.)
│   │   ├── elf/                     # ELF parser and helpers
│   │   └── pe/                      # PE parser and helpers (planned)
│   ├── modules/                     # Built-in and custom analysis modules
│   │   ├── common/                  # Generic modules (entropy, strings, etc.)
<<<<<<< HEAD
│   │   ├── elf/                     # ELF-specific
│   │   └── pe/                      # PE-specific
│   ├── scripting/                   # Lua scripting backends
│   ├── main.c                       # Entry point
│   └── config.h                     # Feature flags and global settings
│
├── include/                         # Shared public headers
├── scripts/                         # Lua plugin scripts
=======
│   │   ├── elf/                     # ELF-specific checks (NX, PIE, RELRO...)
│   │   └── pe/                      # PE-specific checks (ASLR, DEP...)
│   ├── scripting/                   # Lua / WASM scripting backends
│   ├── main.c                       # Entry point
│   └── config.h                     # Feature flags and global settings
│
├── include/                         # Shared public headers (optional)
├── scripts/                         # Lua or WASM plugin scripts
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55
├── modules.json                     # Optional plugin metadata registry
├── CMakeLists.txt                   # Build configuration (CMake)
├── Makefile                         # Build wrapper for convenience
├── LICENSE                          # MIT License
└── README.md                        # This file
```

<<<<<<< HEAD
## Roadmap

* [ ] ELF format support
* [ ] Plugin system
* [ ] ncurses TUI (msfconsole-like)
=======
## 🛠️ Roadmap

* [ ] ELF format support
* [ ] Plugin system
* [ ] ncurses TUI
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55
* [ ] JSON export
* [ ] PE format support
* [ ] Mach-O format support
* [ ] Headless CLI-only mode
<<<<<<< HEAD
* [ ] Lua plugin scripting
* [ ] Plugin metadata registry (modules.json dynamic loading)

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

## Contributing
=======
* [ ] Lua/WASM plugin scripting
* [ ] Plugin metadata registry (modules.json dynamic loading)

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

## 🧑‍💻 Contributing
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55

Pull requests are welcome! For major changes, please open an issue first to discuss the proposed addition or fix.

Contributions are especially welcome in:

* Plugin development
* PE/Mach-O support
<<<<<<< HEAD
* Lua scripting integration
=======
* WASM/Lua scripting integration
>>>>>>> 952559b828f0673552e825516f48d0f1c2aa0e55
* UI and UX improvements
* Documentation
