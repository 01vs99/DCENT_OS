#!/usr/bin/env python3
"""Find production Rust environment readers outside the shared lab boundary.

This is a focused source inventory, not a Rust type checker. It tokenizes Rust
comments/literals, excludes cfg(test) items and their external modules, and flags
raw readers (including imports that could alias them). Exceptions identify the
operational or refusal-only reader, not a hash of the surrounding implementation.
Run from any directory; --inventory prints every remaining raw reader.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


CRATES = (
    "dcentrald", "dcentrald-common", "dcentrald-hal", "dcentrald-asic",
    "dcentrald-thermal", "dcentrald-autotuner", "dcentrald-silicon-profiles",
    "dcentrald-api",
)
READ_APIS = {"var", "var_os", "vars", "vars_os"}


@dataclass(frozen=True)
class Token:
    value: str
    start: int
    end: int
    literal: bool = False


@dataclass(frozen=True)
class Reader:
    path: str
    line: int
    function: str
    api: str
    argument: str

    def describe(self) -> str:
        return f"{self.path}:{self.line}: {self.function}: {self.api}({self.argument})"


def tokenize(source: str) -> list[Token]:
    """Keep literals opaque and offsets intact, including nested block comments."""
    result = []
    i = 0
    while i < len(source):
        if source[i].isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
            continue
        if source.startswith("/*", i):
            depth = 1
            i += 2
            while i < len(source) and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        raw = re.compile(r'(?:br|cr|r)(\#*)"').match(source, i)
        if raw:
            closing = '"' + raw.group(1)
            end = source.find(closing, raw.end())
            end = len(source) if end < 0 else end + len(closing)
            result.append(Token(source[i:end], i, end, True))
            i = end
            continue
        quoted = re.compile(r'(?:b|c)?"').match(source, i)
        char = re.compile(r"(?:b)?'(?:[^'\\\n]|\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.))'").match(source, i)
        if char:
            end = char.end()
            result.append(Token(source[i:end], i, end, True))
            i = end
            continue
        if quoted:
            end = quoted.end()
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            result.append(Token(source[i:end], i, end, True))
            i = end
            continue
        ident = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|::|->|=>").match(source, i)
        end = ident.end() if ident else i + 1
        result.append(Token(source[i:end], i, end))
        i = end
    return result


def matching(tokens: list[Token], start: int) -> int:
    opening = tokens[start].value
    closing = {"(": ")", "[": "]", "{": "}"}[opening]
    depth = 0
    for i in range(start, len(tokens)):
        if tokens[i].literal:
            continue
        if tokens[i].value == opening:
            depth += 1
        elif tokens[i].value == closing:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"unclosed {opening} at source byte {tokens[start].start}")


def production_tokens(source: str) -> tuple[list[Token], list[tuple[str, str | None]]]:
    tokens = tokenize(source)
    ignored: set[int] = set()
    external_tests = []
    i = 0
    while i < len(tokens):
        if tokens[i].value != "#":
            i += 1
            continue
        first = i
        attrs = []
        inner = False
        while i < len(tokens) and tokens[i].value == "#":
            i += 1
            if tokens[i].value == "!":
                inner = True
                i += 1
            if tokens[i].value != "[":
                break
            end = matching(tokens, i)
            attrs.append(tokens[i + 1:end])
            i = end + 1
        test_only = any(
            [t.value for t in a] == ["cfg", "(", "test", ")"]
            or (
                [t.value for t in a[:4]] == ["cfg", "(", "all", "("]
                and "test" in [t.value for t in a]
                and not {"not", "any"}.intersection(t.value for t in a)
            ) for a in attrs
        )
        if not test_only:
            continue
        if inner:
            return [], []
        # Field/variant/expression cfg attributes do not delimit an item body.
        # Leave those in the inventory rather than accidentally swallowing a
        # surrounding production function at the next opening brace.
        item = i
        while item < len(tokens) and tokens[item].value in {"pub", "async", "unsafe"}:
            item += 1
            if item < len(tokens) and tokens[item].value == "(":
                item = matching(tokens, item) + 1
        if item == len(tokens) or tokens[item].value not in {"fn", "mod", "const", "static", "impl", "struct", "enum", "use"}:
            continue
        body = i
        while body < len(tokens) and tokens[body].value not in {"{", ";"}:
            body = matching(tokens, body) + 1 if tokens[body].value in {"(", "["} else body + 1
        if body == len(tokens):
            raise ValueError("cfg(test) item has no body or semicolon")
        end = matching(tokens, body) if tokens[body].value == "{" else body
        if tokens[body].value == ";":
            declaration = [t.value for t in tokens[i:body]]
            if "mod" in declaration:
                name = declaration[declaration.index("mod") + 1]
                path_attr = next((a[2].value.strip('"') for a in attrs
                                  if len(a) == 3 and a[0].value == "path"), None)
                external_tests.append((name, path_attr))
        ignored.update(range(first, end + 1))
        i = end + 1
    return [t for i, t in enumerate(tokens) if i not in ignored], external_tests


def readers_in_source(path: str, source: str) -> list[Reader]:
    tokens, _ = production_tokens(source)
    functions = []
    for i, token in enumerate(tokens[:-1]):
        if token.value != "fn" or token.literal:
            continue
        body = i + 2
        while body < len(tokens) and tokens[body].value not in {"{", ";"}:
            body += 1
        if body < len(tokens) and tokens[body].value == "{":
            end = matching(tokens, body)
            functions.append((body, end, tokens[i + 1].value))

    readers = []
    for i, token in enumerate(tokens):
        if token.literal or token.value not in {"std", "env", "use"}:
            continue
        values = [t.value for t in tokens[i:i + 6]]
        function = next((name for begin, end, name in reversed(functions)
                         if begin < i < end), "<module>")
        api = argument = None
        if values[:4] == ["std", "::", "env", "::"] and len(values) == 6:
            if values[4] in READ_APIS:
                api = values[4]
                argument = "<function reference>"
                if values[5] == "(":
                    end = matching(tokens, i + 5)
                    argument = "".join(t.value for t in tokens[i + 6:end])
        elif values[:2] == ["env", "::"] and i > 0 and tokens[i - 1].value != "::":
            if len(values) >= 4 and values[2] in READ_APIS:
                api = values[2]
                argument = "<function reference>"
                if values[3] == "(":
                    end = matching(tokens, i + 3)
                    argument = "".join(t.value for t in tokens[i + 4:end])
        # Raw aliases are rejected at the import, so spelling changes cannot
        # evade the boundary. VarError/Args/other non-reader imports are fine.
        if token.value == "use":
            end = i
            while end < len(tokens) and tokens[end].value != ";":
                end += 1
            imported = [t.value for t in tokens[i + 1:end]]
            if "std" in imported and "env" in imported:
                tail = imported[imported.index("env") + 1:]
                if not tail or tail[0] in {"as", ",", "}"} or READ_APIS.intersection(tail) or {"*", "self"}.intersection(tail):
                    api, argument = "raw-env-import", "".join(imported)
        if api is not None:
            readers.append(Reader(path, source.count("\n", 0, token.start) + 1,
                                  function, api, argument))
    return readers


# Exact operational exceptions are deliberately narrow. A new hardware reader
# in one of these files still fails unless its function/argument is reviewed.
ALLOW: dict[tuple[str, str, str], str] = {}


def allow(path: str, function: str, arguments: tuple[str, ...], reason: str) -> None:
    for argument in arguments:
        ALLOW[(path, function, argument)] = reason


allow("dcentrald-common/src/lab_env.rs", "var", ("name",), "the cfg(feature=lab) adapter")
allow("dcentrald-common/src/lab_env.rs", "var_os", ("name",), "the cfg(feature=lab) adapter")
allow("dcentrald/src/am3_bb_mining.rs", "forbidden_override_is_present", ("name",),
      "presence can only refuse the watched mining recipe")
allow("dcentrald/src/main.rs", "main", ('"DCENT_S19K_STARTUP_BOOTSTRAP"',),
      "presence can only refuse native no-work initialization under an inherited custody bootstrap")
allow("dcentrald/src/wave55a_recipe_guard.rs", "runtime_guard_environment", ("name",),
      "bounded forbidden lists and refusal-scope fingerprint only; granting bypass/carve-outs use lab_env")
allow("dcentrald/src/bin/dcentos_discovery.rs", "<module>", ("std::env",), "hostname/CLI metadata import")
allow("dcentrald/src/bin/dcentos_discovery.rs", "detect_hostname", ('"HOSTNAME"',), "discovery identity metadata")
allow("dcentrald/src/bridge_glue.rs", "load_unit_secret", ("UNIT_SECRET_ENV",), "unit authentication secret")
allow("dcentrald/src/logging.rs", "init_logging", ('"DCENTRALD_LOG"', '"RUST_LOG"', '"RUST_LOG_STYLE"'), "logging configuration")
allow("dcentrald/src/metrics_export.rs", "metrics_storage_dir", ("METRICS_DIR_ENV",), "metrics output directory")
allow("dcentrald/src/persistent_log_ring.rs", "default_log_ring_dir", ("LOG_RING_DIR_ENV",), "log output directory")
allow("dcentrald/src/persistent_log_ring.rs", "log_ring_disabled_by_env", ("LOG_RING_DISABLE_ENV",), "log persistence configuration")
allow("dcentrald/src/runtime_policy.rs", "ephemeral_runtime_enabled", ("EPHEMERAL_RUNTIME_ENV",), "ephemeral storage policy")
allow("dcentrald-common/src/mutation_disposition.rs", "from_env", ("SESSION_REASON_ENV",), "mutation audit session reason")
allow("dcentrald-common/src/mutation_disposition.rs", "current_slot_image_identity",
      ("key", "SLOT_IDENTITY_UNAME_ENV", '"HOSTNAME"'), "image/slot identity metadata for audit")
allow("dcentrald-asic/src/dspic/recovery_fw86.rs", "path_c_log_path", ('"DCENT_PIC_RECOVERY_LOG_DIR"',), "recovery audit log location")
allow("dcentrald-api/src/csrf_allowlist.rs", "extra_allowed_hosts", ("CSRF_ALLOWED_HOSTS_ENV",), "HTTP origin allowlist")
allow("dcentrald-api/src/lib.rs", "audit_log_path", ("EPHEMERAL_RUNTIME_ENV", "AUDIT_LOG_PATH_ENV"), "audit storage policy")
allow("dcentrald-api/src/lib.rs", "audit_log_max_bytes", ("AUDIT_LOG_MAX_BYTES_ENV",), "audit log size limit")
allow("dcentrald-api/src/routes/profiles.rs", "profile_dir", ("PROFILE_DIR_ENV",), "saved profile directory")
for function in ("get_env_recipe", "get_mining_handoff_state"):
    allow("dcentrald-api/src/rest/late.rs", function, ("name",), "read-only environment diagnostics, no mutation authority")

# These variables bind an already required startup-wrapper identity and exact
# process/FIFO/fd ownership. Filtering them through lab_env would break safety.
_serial = "dcentrald/src/serial_mining.rs"
for function, arguments in {
    "s19k_arm_permanent_pdeathsig_from_env": ('"DCENT_S19K_STARTUP_BOOTSTRAP"', '"DCENT_S19K_STARTUP_WRAPPER_PID"', '"DCENT_S19K_STARTUP_WRAPPER_START"', ""),
    "s19k_durable_replace_from_cli": ('"DCENT_S19K_STARTUP_WRAPPER_PID"', '"DCENT_S19K_STARTUP_WRAPPER_START"'),
    "s19k_require_exact_daemon_environment": ("",),
    "open_and_require_j0": ('"DCENT_S19K_STARTUP_FIFO"',),
    "s19k_complete_daemon_pre_runtime_bootstrap": ('"DCENT_S19K_STARTUP_WRAPPER_PID"', '"DCENT_S19K_STARTUP_WRAPPER_START"'),
    "s19k_require_exact_daemon_fd_set": ('"DCENT_S19K_STARTUP_LOG"', '"DCENT_S19K_STARTUP_WRAPPER_PID"', '"DCENT_S19K_STARTUP_WRAPPER_START"', '"DCENT_S19K_STARTUP_FIFO"'),
}.items():
    allow(_serial, function, arguments, "required startup wrapper/process identity protocol")
for function in (
    "s19k_capture_and_require_bound_live_identity", "s19k_require_journal_tree_and_artifacts",
    "require_fresh_live_identity", "s19k_parse_runtime_binding_once", "run",
):
    allow(_serial, function, ("S19K_LIVE_IDENTITY_ENV",), "required live hardware identity binding")
allow(_serial, "s19k_track1_maybe_planned_stop_safeoff", ("S19K_TRACK1_STOP_SAFEOFF_ENV",),
      "reject unsafe STOP_SAFEOFF values; safe shutdown remains mandatory")
allow(_serial, "bm1362_forbidden_post_power_reset_override", ('"DCENT_BM1362_SKIP_POST_POWER_RESET"',),
      "reject forbidden reset skipping before direct serial hardware construction")

# Simulator selection is only compiled with sim-hal, which forwards common/lab;
# signed runtime admission rejects that binary through feature unification.
allow("dcentrald/src/sim_runtime.rs", "run", ('"DCENT_SIM_MODEL"',), "simulator model selection")
allow("dcentrald-hal/src/platform/sim/mod.rs", "sim_environment_is_mentioned", ("name",), "explicit simulator session selection")
allow("dcentrald-hal/src/platform/sim/mod.rs", "from_env",
      ("SIM_ALLOW_ENV", "SIM_ACK_ENV", "SIM_MODEL_ENV", "SCAFFOLD_ALLOW_ENV", "SCAFFOLD_ACK_ENV"),
      "simulator session and scaffold acknowledgments, never physical hardware authority")


def is_allowed(reader: Reader) -> bool:
    return (reader.path, reader.function, reader.argument) in ALLOW


def scan_tree(workspace: Path) -> list[Reader]:
    paths = sorted(path for crate in CRATES for path in (workspace / crate / "src").rglob("*.rs"))
    sources = {path: path.read_text(encoding="utf-8") for path in paths}
    excluded = set()
    for path, source in sources.items():
        _, modules = production_tokens(source)
        for name, explicit in modules:
            if explicit:
                excluded.add((path.parent / explicit).resolve())
            else:
                base = path.parent if path.name in {"lib.rs", "main.rs", "mod.rs"} else path.with_suffix("")
                excluded.update([(base / f"{name}.rs").resolve(), (base / name / "mod.rs").resolve()])
    return [reader for path, source in sources.items() if path.resolve() not in excluded
            for reader in readers_in_source(path.relative_to(workspace).as_posix(), source)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", action="store_true", help="list allowed and unresolved raw readers")
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1] / "dcentrald")
    args = parser.parse_args()
    missing = [crate for crate in CRATES if not (args.workspace / crate / "src").is_dir()]
    if missing:
        parser.error(f"source inventory is incomplete; missing crate source directories: {', '.join(missing)}")
    readers = scan_tree(args.workspace)
    refused = [reader for reader in readers if not is_allowed(reader)]
    for reader in readers if args.inventory else refused:
        status = "allowed" if is_allowed(reader) else "UNCONVERTED"
        print(f"{status}: {reader.describe()}")
    if refused:
        print(f"FAIL: {len(refused)} production environment readers must use lab_env or an explicit reviewed operational/refusal reader.")
        return 1
    print(f"PASS: hardware environment reads use lab_env; {len(readers)} operational/refusal readers reviewed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
