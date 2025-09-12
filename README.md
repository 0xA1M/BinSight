# BinSight

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

- GCC or Clang
- [CMake](https://cmake.org/)
- `ncurses` development headers (`libncurses-dev` or similar)
- `libmagic` development headers (`libmagic` or similar)

### Build

```bash
make            # or use cmake ..
````

### ▶️ Run

```bash
./binsight /path/to/binary
```

## Plugin System

BinSight is built around a modular plugin system. Each plugin defines:

```c
typedef struct {
    const char *name;
    const char *description;
    bool (*supports_format)(BinaryFormat fmt);
    char* (*run)(const BinaryFile *bin);
} Plugin;
```

### Adding a Module

1. Create your plugin source file in `src/modules/<format>/`.
2. Implement the `Plugin` interface.
3. Register it in the module registry (static for now).
4. Rebuild the binary — your plugin will appear in the TUI/CLI interface.

## Directory Structure

```text
bin-analyzer/
├── src/
│   ├── core/                        # Core engine (Arena Allocator, Error handler, Dispatcher...etc)
│   ├── formats/                     # Format loaders (ELF, PE, etc.)
│   │   ├── elf/                     # ELF parser and helpers
│   │   └── pe/                      # PE parser and helpers (planned)
│   ├── modules/                     # Built-in and custom analysis modules
│   │   ├── common/                  # Generic modules (entropy, strings, etc.)
│   │   ├── elf/                     # ELF-specific
│   │   └── pe/                      # PE-specific
│   ├── scripting/                   # Lua scripting backends
│   ├── main.c                       # Entry point
│   └── config.h                     # Feature flags and global settings
│
├── include/                         # Shared public headers
├── scripts/                         # Lua plugin scripts
├── modules.json                     # Optional plugin metadata registry
├── CMakeLists.txt                   # Build configuration (CMake)
├── Makefile                         # Build wrapper for convenience
├── LICENSE                          # MIT License
└── README.md                        # This file
```

## Roadmap

* [ ] ELF format support
* [ ] Plugin system
* [ ] ncurses TUI (msfconsole-like)
* [ ] JSON export
* [ ] PE format support
* [ ] Mach-O format support
* [ ] Headless CLI-only mode
* [ ] Lua plugin scripting
* [ ] Plugin metadata registry (modules.json dynamic loading)

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss the proposed addition or fix.

Contributions are especially welcome in:

* Plugin development
* PE/Mach-O support
* Lua scripting integration
* UI and UX improvements
* Documentation
