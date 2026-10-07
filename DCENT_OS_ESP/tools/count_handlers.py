#!/usr/bin/env python3
"""count_handlers.py - DCENT_axe embedded HTTP URI-handler census, by INVOCATION.

WHY THIS EXISTS
===============
`dcentaxe` runs an ESP-IDF HTTP server whose `max_uri_handlers` is a HARD
compile-time budget (`MAX_URI_HANDLERS` in `dcentaxe/src/main.rs`, currently 96).
Registering more URIs than the cap makes `httpd_register_uri_handler()` fail at
boot; this project has boot-looped against the old 64 cap, which is why the cap
is a named const with a compile-time floor guard and a runtime tripwire.

The budget used to be tracked by counting occurrences of the *text*
`.fn_handler(` in the sources.  That UNDER-COUNTS.  A registration written inside
a helper - a `fn`, or a `let name = |path: &str, ...|` closure, or a
`for path in &[...]` loop - is written ONCE but *executed* once per invocation.
Four such helpers exist today (three closures in `api.rs`, `register_static` in
`dashboard.rs`) plus one captive-portal loop in `provisioning.rs`; between them,
5 text occurrences produce 26 registrations.

Text counting is therefore a blind spot, not a conservative estimate: it reports
FEWER handlers than the firmware actually registers, which is the dangerous
direction for a cap that fails at boot.

WHAT THIS SCRIPT DOES
=====================
It reads the Rust sources with a Rust-aware masker (comments, string literals -
including raw and byte strings - and char literals are blanked so they can never
be mistaken for code), finds every `.fn_handler(` *call site*, and resolves how
many URIs each site actually registers at run time:

    registrations(site) = sum over resolution instances of
                          invocations(the scope that produced that instance)

Resolution rules, in order:
  1. First argument is a string literal          -> 1 URI, weighted by the
                                                    invocation count of the
                                                    innermost enclosing scope.
  2. First argument is an identifier that is a
     parameter of the enclosing `fn`/closure     -> one URI per call site of
                                                    that helper, each weighted by
                                                    the invocation count of the
                                                    scope containing the call.
  3. First argument is an identifier bound by an
     enclosing `for <ident> in &[ "a", "b", .. ]`-> one URI per array element.

Invocation counts come from a call graph over the crate's `fn` items, rooted at
the server entry points that `main.rs` actually wires to a server (verified, not
assumed).  A registration site whose enclosing `fn` is unreachable from any root
contributes 0 and is reported as DEAD.

Registrations are attributed to the SERVER they land on, because `dcentaxe` runs
two: the main dashboard/API/MCP server (`MAX_URI_HANDLERS`) and the short-lived
captive-portal server in `provisioning.rs` (its own `EspHttpServer`, default
cap).  Only the main server's total counts against the 96 budget.

USAGE
=====
    python tools/count_handlers.py                  # table + URI list + used/cap
    python tools/count_handlers.py --json           # machine-readable
    python tools/count_handlers.py --quiet          # totals only
    python tools/count_handlers.py --root <path>    # crate root (default: auto)

Exit codes: 0 = the census is complete, trusted, under the cap, and agrees with
`REGISTERED_HANDLER_ESTIMATE`.  1 = anything else.  Fail-closed, because every
one of these means the census cannot be trusted, and an untrusted census
UNDER-reports, which is the direction that fails at boot:
  * a registration over the cap;
  * an unresolved registration site (a first argument this parser cannot read);
  * a DEAD site - a `.fn_handler(` whose enclosing fn is not reachable from any
    wiring root in SERVERS.  Round 1 of lane P1-I3 printed those as an
    informational row and still exited 0, so wiring a handler in from a file the
    census does not know about looked green;
  * DRIFT between `REGISTERED_HANDLER_ESTIMATE` and the measured total, or a
    tripwire that would fire.  Same reason: the report said `DRIFT`, the exit
    code said 0, and an operator reading exit codes saw green.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Configuration: the servers, and where their roots are.
# The main-server roots are ASSERTED against main.rs, so a future refactor that
# stops wiring one of them (or wires a new one) fails this script instead of
# silently changing the count.
# --------------------------------------------------------------------------

REGISTER_CALL = ".fn_handler("

MAIN_SERVER_WIRING = [
    # (expected substring in main.rs, module::fn that owns the registrations)
    ("dashboard::register_dashboard(&mut http_server)", ("dashboard.rs", "register_dashboard")),
    ("api::register_api(&mut http_server", ("api.rs", "register_api")),
    ("mcp::register_mcp(&mut http_server", ("mcp.rs", "register_mcp")),
]

PORTAL_SERVER_WIRING = [
    ("provisioning::run_provisioning(", ("provisioning.rs", "run_provisioning")),
]

SERVERS = [
    {
        "id": "main",
        "title": "main HTTP server (dashboard + REST API + MCP)",
        "wiring": MAIN_SERVER_WIRING,
        "cap_const": "MAX_URI_HANDLERS",
        "counts_against_budget": True,
    },
    {
        "id": "portal",
        "title": "captive-portal server (provisioning AP, own EspHttpServer)",
        "wiring": PORTAL_SERVER_WIRING,
        # esp-idf-svc `http::server::Configuration::default()` -> max_uri_handlers: 32
        "cap_const": None,
        "default_cap": 32,
        "counts_against_budget": False,
    },
]


# --------------------------------------------------------------------------
# Rust-aware masking
# --------------------------------------------------------------------------

_RAW_PREFIX = re.compile(r"(?:b?r)(#*)\"")
_CHAR_LIT = re.compile(r"'(?:\\[^']*|[^\\'])'")


def mask_source(src: str) -> str:
    """Return `src` with comments and literal *contents* blanked to spaces.

    Length and newline positions are preserved, so any offset into the mask is a
    valid offset into the original.  Ordinary `"..."` string literals keep their
    delimiting quotes (so a literal first argument is still recognisable) but
    lose their contents; raw and byte-raw strings are blanked entirely, prefix
    and delimiters included, because they are never used as a URI argument and
    their embedded quotes would otherwise confuse the scan.
    """
    out = list(src)
    n = len(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    i = 0
    while i < n:
        c = src[i]

        # line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
            continue

        # block comment (Rust nests them)
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue

        # raw / byte-raw string: r"..", r#".."#, br##".."##
        if c in "rb":
            # only a real prefix if the preceding char cannot continue an ident
            prev_ok = i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")
            m = _RAW_PREFIX.match(src, i) if prev_ok else None
            if m:
                term = '"' + m.group(1)
                j = src.find(term, m.end())
                j = n if j == -1 else j + len(term)
                blank(i, j)
                i = j
                continue

        # ordinary or byte string
        if c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i + 1, j - 1)
            i = j
            continue

        # char literal (but NOT a lifetime: 'a, 'static)
        if c == "'":
            m = _CHAR_LIT.match(src, i)
            if m:
                blank(i, m.end())
                i = m.end()
                continue
            i += 1
            continue

        i += 1

    return "".join(out)


# --------------------------------------------------------------------------
# Lightweight Rust structure parsing (over the masked text)
# --------------------------------------------------------------------------

_FN_DEF = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>(){};]*>)?\s*\(")
_CLOSURE_DEF = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;|]*)?=\s*(?:move\s+)?\|"
)
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def match_delims(code: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the delimiter matching the one at `start`."""
    depth = 0
    i = start
    n = len(code)
    while i < n:
        if code[i] == open_ch:
            depth += 1
        elif code[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def top_level_commas(code: str, a: int, b: int) -> List[Tuple[int, int]]:
    """Split code[a:b] on commas that are not nested in (), [] or {}."""
    parts: List[Tuple[int, int]] = []
    depth = 0
    start = a
    for i in range(a, b):
        ch = code[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append((start, i))
            start = i + 1
    parts.append((start, b))
    return parts


def param_names(code: str, a: int, b: int) -> List[str]:
    """Parameter identifiers of a signature body code[a:b] (`name: Type` list)."""
    names: List[str] = []
    for s, e in top_level_commas(code, a, b):
        chunk = code[s:e].strip()
        if not chunk:
            continue
        chunk = chunk.split(":", 1)[0].strip()
        chunk = chunk.replace("mut ", "").replace("&", "").strip()
        names.append(chunk if _IDENT.match(chunk) else "")
    return names


@dataclass
class Scope:
    file: str
    name: str
    kind: str  # "fn" | "closure"
    params: List[str]
    body_start: int
    body_end: int
    parent: Optional["Scope"] = None

    def contains(self, pos: int) -> bool:
        return self.body_start <= pos < self.body_end

    @property
    def span(self) -> int:
        return self.body_end - self.body_start


@dataclass
class RustFile:
    path: str  # repo-relative, forward slashes
    src: str
    code: str  # masked
    scopes: List[Scope] = field(default_factory=list)

    def line_of(self, pos: int) -> int:
        return self.code.count("\n", 0, pos) + 1


def parse_scopes(rf: RustFile) -> None:
    code = rf.code
    n = len(code)

    for m in _FN_DEF.finditer(code):
        name = m.group(1)
        open_paren = m.end() - 1
        close_paren = match_delims(code, open_paren, "(", ")")
        params = param_names(code, open_paren + 1, close_paren - 1)
        # body starts at the next '{' that is not part of a return type
        j = code.find("{", close_paren)
        if j == -1:
            continue
        semi = code.find(";", close_paren)
        if semi != -1 and semi < j:
            continue  # a trait/extern signature without a body
        end = match_delims(code, j, "{", "}")
        rf.scopes.append(Scope(rf.path, name, "fn", params, j + 1, end - 1))

    for m in _CLOSURE_DEF.finditer(code):
        name = m.group(1)
        bar = m.end() - 1
        close_bar = code.find("|", bar + 1)
        if close_bar == -1:
            continue
        params = param_names(code, bar + 1, close_bar)
        k = close_bar + 1
        while k < n and code[k].isspace():
            k += 1
        # skip an explicit return type: `-> Type {`
        if code.startswith("->", k):
            k = code.find("{", k)
            if k == -1:
                continue
        if k < n and code[k] == "{":
            end = match_delims(code, k, "{", "}")
            rf.scopes.append(Scope(rf.path, name, "closure", params, k + 1, end - 1))

    rf.scopes.sort(key=lambda s: (s.body_start, -s.span))
    for s in rf.scopes:
        best: Optional[Scope] = None
        for cand in rf.scopes:
            if cand is s:
                continue
            if cand.body_start <= s.body_start and s.body_end <= cand.body_end:
                if best is None or cand.span < best.span:
                    best = cand
        s.parent = best


def innermost_scope(rf: RustFile, pos: int) -> Optional[Scope]:
    best: Optional[Scope] = None
    for s in rf.scopes:
        if s.contains(pos) and (best is None or s.span < best.span):
            best = s
    return best


def outermost_fn(scope: Optional[Scope]) -> Optional[Scope]:
    top = None
    while scope is not None:
        if scope.kind == "fn":
            top = scope
        scope = scope.parent
    return top


# --------------------------------------------------------------------------
# Call sites
# --------------------------------------------------------------------------


def call_sites(rf: RustFile, name: str, a: int = 0, b: Optional[int] = None) -> List[int]:
    """Offsets of `name(` calls in code[a:b], excluding `fn name(` definitions."""
    b = len(rf.code) if b is None else b
    out: List[int] = []
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", rf.code[a:b]):
        pos = a + m.start()
        prefix = rf.code[max(0, pos - 8):pos]
        if re.search(r"\bfn\s+$", prefix):
            continue
        out.append(pos)
    return out


def call_arg(rf: RustFile, call_pos: int, name: str, index: int) -> Optional[Tuple[int, int]]:
    open_paren = rf.code.find("(", call_pos + len(name) - 1)
    if open_paren == -1:
        return None
    close_paren = match_delims(rf.code, open_paren, "(", ")") - 1
    parts = top_level_commas(rf.code, open_paren + 1, close_paren)
    if index >= len(parts):
        return None
    return parts[index]


def literal_at(rf: RustFile, span: Tuple[int, int]) -> Optional[str]:
    a, b = span
    chunk = rf.code[a:b].strip()
    if not chunk.startswith('"'):
        return None
    off = rf.code.index('"', a)
    end = rf.code.index('"', off + 1)
    return rf.src[off + 1:end]


# --------------------------------------------------------------------------
# Census
# --------------------------------------------------------------------------


@dataclass
class Registration:
    server: str
    file: str
    line: int
    uri: str
    method: str
    via: str
    weight: int


@dataclass
class SiteReport:
    file: str
    line: int
    scope: str
    kind: str  # "direct" | "helper-fn" | "helper-closure" | "for-loop" | "dead" | "unresolved"
    registrations: int
    detail: str


def load_files(src_root: str, repo_root: str) -> Dict[str, RustFile]:
    files: Dict[str, RustFile] = {}
    for dirpath, _dirnames, filenames in os.walk(src_root):
        for fn in sorted(filenames):
            if not fn.endswith(".rs"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, repo_root).replace("\\", "/")
            # Text mode (universal newlines) collapses CRLF to LF, so the census
            # is identical on a CRLF worktree and an LF main tree. This repo has
            # `core.autocrlf = true`, so both exist at once; do not switch this
            # to binary reads without re-normalising.
            with open(full, "r", encoding="utf-8") as fh:
                src = fh.read()
            rf = RustFile(rel, src, mask_source(src))
            parse_scopes(rf)
            files[rel] = rf
    return files


def build_invocations(
    files: Dict[str, RustFile], roots: Sequence[Tuple[str, str]]
) -> Dict[Tuple[str, str], int]:
    """invocations[(file, fn)] for every fn reachable from `roots` (each root = 1)."""
    fn_index: Dict[str, List[Scope]] = {}
    for rf in files.values():
        for s in rf.scopes:
            if s.kind == "fn" and s.parent is None:
                fn_index.setdefault(s.name, []).append(s)

    counts: Dict[Tuple[str, str], int] = {}
    order: List[Tuple[str, str]] = []
    for root in roots:
        counts[root] = counts.get(root, 0) + 1
        order.append(root)

    seen = set()
    while order:
        key = order.pop(0)
        if key in seen:
            continue
        seen.add(key)
        rel, name = key
        rf = files.get(rel)
        if rf is None:
            continue
        scope = next(
            (s for s in rf.scopes if s.kind == "fn" and s.name == name and s.parent is None),
            None,
        )
        if scope is None:
            continue
        weight = counts[key]
        for callee_name, defs in fn_index.items():
            if callee_name == name:
                continue
            hits = call_sites(rf, callee_name, scope.body_start, scope.body_end)
            if not hits:
                continue
            # prefer a definition in the same file (private helper), else unique global
            same = [d for d in defs if d.file == rel]
            target = same[0] if same else (defs[0] if len(defs) == 1 else None)
            if target is None:
                continue
            ck = (target.file, target.name)
            counts[ck] = counts.get(ck, 0) + weight * len(hits)
            order.append(ck)
    return counts


def enclosing_for_loop(rf: RustFile, ident: str, scope: Scope, pos: int) -> Optional[List[str]]:
    """Resolve `for <ident> in &[ "a", "b", ... ]` enclosing `pos`."""
    pat = re.compile(r"\bfor\s+" + re.escape(ident) + r"\s+in\s*&?\s*\[")
    best: Optional[List[str]] = None
    for m in pat.finditer(rf.code, scope.body_start, pos):
        bracket = m.end() - 1
        end = match_delims(rf.code, bracket, "[", "]")
        body_end = rf.code.find("{", end)
        if body_end == -1:
            continue
        block_end = match_delims(rf.code, body_end, "{", "}")
        if not (body_end <= pos < block_end):
            continue
        uris: List[str] = []
        for a, b in top_level_commas(rf.code, bracket + 1, end - 1):
            lit = literal_at(rf, (a, b))
            if lit is not None:
                uris.append(lit)
        best = uris
    return best


def census(repo_root: str, esp_root: str) -> dict:
    src_root = os.path.join(esp_root, "dcentaxe", "src")
    files = load_files(src_root, repo_root)

    main_rel = os.path.relpath(
        os.path.join(src_root, "main.rs"), repo_root
    ).replace("\\", "/")
    main_rf = files[main_rel]

    # 1. Verify the wiring, then build one invocation map per server.
    server_invocations: Dict[str, Dict[Tuple[str, str], int]] = {}
    wiring_report: List[str] = []
    problems: List[str] = []
    for server in SERVERS:
        roots: List[Tuple[str, str]] = []
        for needle, (fname, fnname) in server["wiring"]:
            if needle not in main_rf.code and needle not in main_rf.src:
                problems.append(
                    f"main.rs no longer wires `{needle}` - server `{server['id']}` "
                    f"root ({fname}::{fnname}) is unverified"
                )
                continue
            rel = next((r for r in files if r.endswith("/" + fname)), None)
            if rel is None:
                problems.append(f"source file {fname} not found for server `{server['id']}`")
                continue
            roots.append((rel, fnname))
            wiring_report.append(f"{server['id']}: {needle}  ->  {rel}::{fnname}")
        server_invocations[server["id"]] = build_invocations(files, roots)

    # 2. Walk every `.fn_handler(` call site.
    registrations: List[Registration] = []
    sites: List[SiteReport] = []
    text_sites: Dict[str, int] = {}

    for rel in sorted(files):
        rf = files[rel]
        idx = 0
        while True:
            pos = rf.code.find(REGISTER_CALL, idx)
            if pos == -1:
                break
            idx = pos + len(REGISTER_CALL)
            text_sites[rel] = text_sites.get(rel, 0) + 1
            line = rf.line_of(pos)
            scope = innermost_scope(rf, pos)
            top = outermost_fn(scope)
            scope_name = f"{scope.name}" if scope else "<file scope>"

            # which server owns this site?
            server_id = None
            weight = 0
            if top is not None:
                for sid, inv in server_invocations.items():
                    w = inv.get((top.file, top.name), 0)
                    if w:
                        server_id = sid
                        weight = w
                        break
            if server_id is None:
                # FAIL-CLOSED (P1-I3 round 2). A `.fn_handler(` whose enclosing fn
                # is not reachable from a wiring root this script knows about used
                # to be reported as an informational `dead` row while the script
                # still exited 0 and kept `measured = 76 OK`.  That is exactly the
                # blind spot this tool exists to remove, moved up one level: a new
                # `foo::register_foo(&mut http_server)` line in main.rs registers
                # real URIs the census does not count, so the census UNDER-reports,
                # which is the direction that fails at boot.  Wiring the site into
                # SERVERS (or proving it truly dead and deleting it) is the fix; an
                # exit code of 0 is not.
                sites.append(
                    SiteReport(rel, line, scope_name, "dead", 0,
                               "enclosing fn is unreachable from any wired server root")
                )
                problems.append(
                    f"{rel}:{line}: `.fn_handler(` inside `{scope_name}` is not "
                    f"reachable from any wiring root in SERVERS, so its URIs are "
                    f"NOT counted. Either add the owning `main.rs` wiring needle to "
                    f"MAIN_SERVER_WIRING/PORTAL_SERVER_WIRING, or delete the dead "
                    f"registration. An uncounted registration under-counts the cap."
                )
                continue

            open_paren = pos + len(REGISTER_CALL) - 1
            close_paren = match_delims(rf.code, open_paren, "(", ")") - 1
            args = top_level_commas(rf.code, open_paren + 1, close_paren)
            arg0 = args[0] if args else (open_paren + 1, close_paren)
            method = "?"
            if len(args) > 1:
                m = re.search(r"Method::(\w+)", rf.code[args[1][0]:args[1][1]])
                if m:
                    method = m.group(1).upper()

            lit = literal_at(rf, arg0)
            if lit is not None:
                registrations.append(
                    Registration(server_id, rel, line, lit, method, "direct", weight)
                )
                sites.append(SiteReport(rel, line, scope_name, "direct", weight, lit))
                idx = close_paren
                continue

            ident = rf.code[arg0[0]:arg0[1]].strip()
            if not _IDENT.match(ident):
                problems.append(f"{rel}:{line}: unparsable first argument {ident!r}")
                sites.append(SiteReport(rel, line, scope_name, "unresolved", 0, ident))
                continue

            # (2) parameter of an enclosing fn/closure -> one URI per call site
            holder = scope
            resolved = False
            while holder is not None:
                if ident in holder.params:
                    param_index = holder.params.index(ident)
                    search_from, search_to = (0, len(rf.code))
                    if holder.kind == "closure" and holder.parent is not None:
                        search_from, search_to = holder.parent.body_start, holder.parent.body_end
                    hits = [
                        h for h in call_sites(rf, holder.name, search_from, search_to)
                        if not holder.contains(h)
                    ]
                    if not hits:
                        problems.append(
                            f"{rel}:{line}: helper `{holder.name}` has no resolvable call site"
                        )
                        sites.append(SiteReport(rel, line, scope_name, "unresolved", 0,
                                                f"{holder.name}: 0 call sites"))
                        resolved = True
                        break
                    total = 0
                    uris: List[str] = []
                    for h in hits:
                        span = call_arg(rf, h, holder.name, param_index)
                        u = literal_at(rf, span) if span else None
                        if u is None:
                            problems.append(
                                f"{rel}:{rf.line_of(h)}: non-literal URI passed to "
                                f"`{holder.name}`"
                            )
                            continue
                        # weight of the scope containing THIS call site
                        call_scope = innermost_scope(rf, h)
                        call_top = outermost_fn(call_scope)
                        w = server_invocations[server_id].get(
                            (call_top.file, call_top.name), 0
                        ) if call_top else 0
                        if holder.kind == "fn":
                            # `holder` itself is the callee; its invocation count is
                            # already the sum over call sites, so weight each call by
                            # its caller's count (identical result, explicit here).
                            pass
                        total += w
                        uris.append(u)
                        registrations.append(
                            Registration(server_id, rel, line, u, method,
                                         f"via {holder.kind} `{holder.name}` "
                                         f"@{rf.line_of(h)}", w)
                        )
                    kind = "helper-fn" if holder.kind == "fn" else "helper-closure"
                    sites.append(SiteReport(
                        rel, line, scope_name, kind, total,
                        f"`{holder.name}` x{len(hits)} -> " + ", ".join(uris)))
                    resolved = True
                    break
                holder = holder.parent
            if resolved:
                idx = close_paren
                continue

            # (3) `for <ident> in &[ ... ]`
            loop_uris = enclosing_for_loop(rf, ident, scope, pos) if scope else None
            if loop_uris:
                for u in loop_uris:
                    registrations.append(
                        Registration(server_id, rel, line, u, method,
                                     f"for-loop over &[..] x{len(loop_uris)}", weight)
                    )
                sites.append(SiteReport(
                    rel, line, scope_name, "for-loop", weight * len(loop_uris),
                    f"&[{len(loop_uris)} paths] -> " + ", ".join(loop_uris)))
                idx = close_paren
                continue

            problems.append(f"{rel}:{line}: could not resolve URI identifier `{ident}`")
            sites.append(SiteReport(rel, line, scope_name, "unresolved", 0, ident))

    # 3. Caps.
    caps: Dict[str, int] = {}
    m = re.search(r"const MAX_URI_HANDLERS:\s*usize\s*=\s*(\d+)\s*;", main_rf.code)
    caps["main"] = int(m.group(1)) if m else -1
    caps["portal"] = 32  # esp-idf-svc Configuration::default().max_uri_handlers

    est = re.search(r"const REGISTERED_HANDLER_ESTIMATE:\s*usize\s*=\s*(\d+)\s*;", main_rf.code)
    estimate = int(est.group(1)) if est else -1

    # 4. Drift + tripwire, FAIL-CLOSED (P1-I3 round 2).
    #
    # These used to be rendered as `DRIFT` / `FIRES` words in the report while the
    # process still returned 0.  A station operator - and every wrapper in
    # `measure_image.{sh,ps1}` - reads the exit code, so a printed DRIFT was
    # indistinguishable from green.  The const in main.rs feeds a compile-time
    # floor assert and a runtime tripwire, so a const that disagrees with reality
    # is a real defect, not a note.
    main_used = sum(r.weight for r in registrations if r.server == "main")
    if estimate < 0:
        problems.append(
            "main.rs no longer declares `const REGISTERED_HANDLER_ESTIMATE` - the "
            "compile-time floor guard and the runtime tripwire have no input"
        )
    elif estimate != main_used:
        problems.append(
            f"REGISTERED_HANDLER_ESTIMATE = {estimate} but the measured main-server "
            f"registration count is {main_used} (drift {main_used - estimate:+d}). "
            f"Update the const AND the accounting table in dcentaxe/src/main.rs, "
            f"then re-run this script."
        )
    if caps["main"] > 0 and estimate >= 0 and estimate + 8 >= caps["main"]:
        problems.append(
            f"runtime tripwire would fire: REGISTERED_HANDLER_ESTIMATE + 8 = "
            f"{estimate + 8} is not below MAX_URI_HANDLERS = {caps['main']}"
        )

    # 5. Duplicate (server, method, URI) registrations, FAIL-CLOSED (P1-I3 round 2
    #    critic held-out finding).  esp-idf-svc rejects the second registration of the
    #    same method+URI at boot, so a collision is a boot-time defect.  This list was
    #    computed for the report but never reached `problems`, the exit code or
    #    `--json` - a literal-for-literal URI swap in api.rs left every gate green.
    dup: Dict[Tuple[str, str, str], int] = {}
    for r in registrations:
        k = (r.server, r.method, r.uri)
        dup[k] = dup.get(k, 0) + r.weight
    duplicates = sorted((sid, meth, uri, n) for (sid, meth, uri), n in dup.items() if n > 1)
    for sid, meth, uri, n in duplicates:
        problems.append(
            f"duplicate registration: server `{sid}` registers {meth} {uri} x{n} - "
            f"the second registration FAILS at boot (esp_http_server rejects it)"
        )

    return {
        "repo_root": repo_root,
        "commit": git_commit(repo_root),
        "wiring": wiring_report,
        "registrations": registrations,
        "sites": sites,
        "text_sites": text_sites,
        "caps": caps,
        "estimate_const": estimate,
        "problems": problems,
        "duplicates": duplicates,
    }


def git_commit(repo_root: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=20,
        )
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def short_path(rel: str) -> str:
    """Display form: drop the `DCENT_OS_ESP/` prefix when present."""
    marker = "dcentos-esp/"
    i = rel.find(marker)
    return rel[i + len(marker):] if i != -1 else rel


def render(result: dict, quiet: bool) -> str:
    regs: List[Registration] = result["registrations"]
    sites: List[SiteReport] = result["sites"]
    caps = result["caps"]
    lines: List[str] = []

    totals: Dict[str, int] = {}
    for r in regs:
        totals[r.server] = totals.get(r.server, 0) + r.weight

    lines.append("DCENT_axe HTTP URI-handler census - counted by INVOCATION, not by text")
    lines.append(f"commit {result['commit']}")
    lines.append("")

    if not quiet:
        lines.append("Server wiring verified in dcentaxe/src/main.rs:")
        for w in result["wiring"]:
            lines.append(f"  {w}")
        lines.append("")

    for server in SERVERS:
        sid = server["id"]
        srv_regs = [r for r in regs if r.server == sid]
        if not srv_regs:
            continue
        used = totals.get(sid, 0)
        cap = caps.get(sid, -1)
        lines.append(f"=== {server['title']} ===")

        per_file: Dict[str, Dict[str, int]] = {}
        for r in srv_regs:
            e = per_file.setdefault(r.file, {"regs": 0})
            e["regs"] += r.weight
        lines.append(f"  {'file':<28}{'text sites':>11}{'registrations':>15}   note")
        text_total = 0
        for f in sorted(per_file):
            t = result["text_sites"].get(f, 0)
            text_total += t
            n = per_file[f]["regs"]
            notes = [
                s.detail for s in sites
                if s.file == f and s.kind in ("helper-fn", "helper-closure", "for-loop")
            ]
            note = ""
            if n != t:
                note = f"+{n - t} from {len(notes)} helper site(s)"
            lines.append(f"  {short_path(f):<28}{t:>11}{n:>15}   {note}")
        lines.append(f"  {'-' * 68}")
        lines.append(f"  {'TOTAL':<28}{text_total:>11}{used:>15}   "
                     f"text count under-counts by {used - text_total}")
        if cap > 0:
            pct = 100.0 * used / cap
            lines.append("")
            lines.append(f"  used/cap: {used}/{cap}  ({pct:.1f}%)  headroom {cap - used}")
        if not server["counts_against_budget"]:
            lines.append("  (separate EspHttpServer - does NOT consume MAX_URI_HANDLERS)")
        lines.append("")

    main_used = totals.get("main", 0)
    main_cap = caps.get("main", -1)
    est = result["estimate_const"]
    lines.append(f"REGISTERED_HANDLER_ESTIMATE (main.rs) = {est}   "
                 f"measured = {main_used}   "
                 f"{'OK' if est == main_used else 'DRIFT (this run FAILS)'}")
    if main_cap > 0:
        trip = est + 8
        lines.append(f"runtime tripwire  estimate + 8 < {main_cap}:  "
                     f"{trip} < {main_cap}  "
                     f"{'OK' if trip < main_cap else 'FIRES (this run FAILS)'}")
    lines.append("")

    if not quiet:
        lines.append("Resolution of every `.fn_handler(` site "
                     "(kind `dead` or `unresolved` = this run FAILS):")
        lines.append(f"  {'site':<34}{'kind':<17}{'regs':>5}  detail")
        for s in sorted(sites, key=lambda s: (s.file, s.line)):
            loc = f"{s.file.rsplit('/', 1)[-1]}:{s.line}"
            detail = s.detail if len(s.detail) < 96 else s.detail[:93] + "..."
            lines.append(f"  {loc:<34}{s.kind:<17}{s.registrations:>5}  {detail}")
        lines.append("")

        for server in SERVERS:
            sid = server["id"]
            srv_regs = [r for r in regs if r.server == sid]
            if not srv_regs:
                continue
            lines.append(f"URI list - {server['title']}:")
            lines.append(f"  {'#':>4}  {'METHOD':<8}{'URI':<46}{'source':<22}via")
            i = 0
            for r in sorted(srv_regs, key=lambda r: (r.file, r.line, r.uri)):
                for _ in range(r.weight):
                    i += 1
                    src = f"{r.file.rsplit('/', 1)[-1]}:{r.line}"
                    lines.append(f"  {i:>4}  {r.method:<8}{r.uri:<46}{src:<22}{r.via}")
            lines.append("")

    if result["duplicates"]:
        lines.append("Duplicate (server, method, URI) registrations - the second one FAILS at boot "
                     "(this run FAILS):")
        for sid, meth, uri, n in result["duplicates"]:
            lines.append(f"  {sid}  {meth} {uri}  x{n}")
        lines.append("")

    if result["problems"]:
        lines.append("PROBLEMS (census cannot be trusted until these are resolved):")
        for p in result["problems"]:
            lines.append(f"  - {p}")
        lines.append("")

    return "\n".join(lines)


def to_json(result: dict) -> dict:
    regs: List[Registration] = result["registrations"]
    totals: Dict[str, int] = {}
    for r in regs:
        totals[r.server] = totals.get(r.server, 0) + r.weight
    per_file: Dict[str, Dict[str, int]] = {}
    for r in regs:
        e = per_file.setdefault(r.file, {"registrations": 0, "text_sites": 0, "server": r.server})
        e["registrations"] += r.weight
    for f in per_file:
        per_file[f]["text_sites"] = result["text_sites"].get(f, 0)
    return {
        "commit": result["commit"],
        "cap": result["caps"].get("main", -1),
        "used": totals.get("main", 0),
        "headroom": result["caps"].get("main", 0) - totals.get("main", 0),
        "estimate_const": result["estimate_const"],
        "estimate_matches_measured": result["estimate_const"] == totals.get("main", 0),
        "per_file": per_file,
        "servers": {
            sid: {"used": totals.get(sid, 0), "cap": result["caps"].get(sid, -1)}
            for sid in totals
        },
        "uris": [
            {"server": r.server, "method": r.method, "uri": r.uri,
             "source": f"{r.file}:{r.line}", "via": r.via, "count": r.weight}
            for r in sorted(regs, key=lambda r: (r.server, r.file, r.line, r.uri))
        ],
        "problems": result["problems"],
        "duplicates": [list(d) for d in result["duplicates"]],
    }


def find_esp_root(explicit: Optional[str]) -> Tuple[str, str]:
    if explicit:
        esp_root = os.path.abspath(explicit)
    else:
        esp_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    repo_root = esp_root
    probe = esp_root
    for _ in range(8):
        if os.path.isdir(os.path.join(probe, ".git")) or os.path.isfile(
            os.path.join(probe, ".git")
        ):
            repo_root = probe
            break
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    return repo_root, esp_root


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", help="path to DCENT_OS_ESP (default: parent of tools/)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--quiet", action="store_true", help="totals only, no URI list")
    args = ap.parse_args(argv)

    repo_root, esp_root = find_esp_root(args.root)
    result = census(repo_root, esp_root)

    if args.json:
        print(json.dumps(to_json(result), indent=2))
    else:
        print(render(result, args.quiet))

    used = sum(r.weight for r in result["registrations"] if r.server == "main")
    cap = result["caps"].get("main", -1)
    if result["problems"]:
        return 1
    if cap > 0 and used > cap:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
