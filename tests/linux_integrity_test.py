#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path
from collections.abc import Generator


# Configuration constants
PROGRAM = Path("../build/binsight")
OUTPUT_DIR = Path("./linux_integrity_test_out")
SEARCH_DIRS = [Path("/bin"), Path("/usr/bin")]
TIMEOUT_SECONDS = 10

def find_executables(directories: list[Path]) -> Generator[Path, None, None]:
    for directory in directories:
        if not directory.exists():
            print(f"Warning: Directory {directory} does not exist", file=sys.stderr)
            continue

        for filepath in directory.rglob("*"):
            if filepath.is_file() and filepath.stat().st_mode & 0o111:
                yield filepath


def run_test(program: Path, target: Path, output_file: Path) -> tuple[bool, int | str]:
    try:
        result = subprocess.run(
            [program, target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,  # Don't raise exception on non-zero exit
        )
        _ = output_file.write_text(result.stdout, encoding="utf-8")
        return result.returncode == 0, result.returncode

    except subprocess.TimeoutExpired:
        _ = output_file.write_text(
            f"Timeout expired ({TIMEOUT_SECONDS}s) running {target}\n"
        )
        return False, "TIMEOUT"

    except Exception as e:
        _ = output_file.write_text(f"Exception running {target}:\n{e}\n")
        return False, "EXCEPTION"


def main() -> None:
    if not PROGRAM.is_file() or not PROGRAM.stat().st_mode & 0o111:
        print(f"Error: {PROGRAM} not found or not executable", file=sys.stderr)
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    success_count = 0
    fail_count = 0
    failures: list[tuple[Path, int | str]] = []

    for filepath in find_executables(SEARCH_DIRS):
        safe_name = str(filepath).replace("/", "_")
        output_file = OUTPUT_DIR / f"{safe_name}.txt"

        success, return_code = run_test(PROGRAM, filepath, output_file)

        if success:
            success_count += 1
        else:
            fail_count += 1
            failures.append((filepath, return_code))

    total_tested = success_count + fail_count

    print("\n=== Integrity Test Summary ===")
    print(f"Total tested: {total_tested}")
    print(f"  ✅ Success: {success_count}")
    print(f"  ❌ Failures: {fail_count}")

    if failures:
        print("\nSample Failures (first 100):")
        for filepath, code in failures[:100]:
            print(f" - {filepath} (exit={code})")
        if len(failures) > 100:
            print(f" ... and {len(failures) - 100} more")

    failure_log = OUTPUT_DIR / "failures.log"
    _ = failure_log.write_text(
        "\n".join(f"{filepath} (exit={code})" for filepath, code in failures),
        encoding="utf-8",
    )

    print(f"\nDetailed outputs saved in {OUTPUT_DIR}")
    print(f"Failures logged in {failure_log}")

    # Critical for CI: exit with failure if there are any failures
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
