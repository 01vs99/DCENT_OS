import csv, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else "live-nvs-extracted.json"
FANS = sys.argv[2] if len(sys.argv) > 2 else "fan2_only"

d = json.load(open(os.path.join(HERE, SRC)))

# --- Patch the DCENT_axe config blob: declare the populated fan header ---
cfg = json.loads(bytes.fromhex(d["dcentaxe"]["config"]["v"]).decode("utf-8"))
before = json.dumps(cfg, separators=(",", ":"), ensure_ascii=False)
cfg["fans_populated"] = FANS
new_cfg = json.dumps(cfg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
d["dcentaxe"]["config"]["v"] = new_cfg.hex()
print(f"config blob {len(before)} -> {len(new_cfg)} bytes; fans_populated={FANS!r}")
print(f"  worker preserved: {cfg['stratum']['worker_name']}")
print(f"  ssid   preserved: {cfg['wifi_ssid']}")

TYPEMAP = {"uint8_t": "u8", "uint16_t": "u16", "uint32_t": "u32", "uint64_t": "u64",
           "int8_t": "i8", "int16_t": "i16", "int32_t": "i32", "int64_t": "i64"}

rows = [["key", "type", "encoding", "value"]]
sidecars = 0
for ns in ("main", "dcentaxe"):
    rows.append([ns, "namespace", "", ""])
    for k, e in d[ns].items():
        if e["t"] == "string":
            # Values containing a comma or newline go to a side file so the CSV
            # stays trivially parseable (themecolors is JSON with both).
            if "," in e["v"] or "\n" in e["v"]:
                fn = f"nvsval_{ns}_{k}.txt"
                open(os.path.join(HERE, fn), "w", encoding="utf-8", newline="").write(e["v"])
                rows.append([k, "file", "string", fn])
                sidecars += 1
            else:
                rows.append([k, "data", "string", e["v"]])
        elif e["t"] == "blob":
            rows.append([k, "data", "hex2bin", e["v"]])
        else:
            rows.append([k, "data", TYPEMAP[e["t"]], str(e["v"])])

path = os.path.join(HERE, "new-nvs.csv")
with open(path, "w", newline="", encoding="utf-8") as f:
    csv.writer(f).writerows(rows)
print(f"wrote {path}: {len(rows)-1} rows, {sidecars} side file(s)")
