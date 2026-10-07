import base64, json, sys

d = json.load(open(sys.argv[1]))
WANT = {"main", "dcentaxe"}

# Namespace declarations live in namespace index 0: key = name, value = index.
ns_name = {}
for page in d["pages"]:
    for e in page.get("entries") or []:
        if e.get("state") != "Written":
            continue
        if (e.get("metadata") or {}).get("namespace") == 0:
            ns_name[e["data"]["value"]] = e["key"]

def children_bytes(e):
    return b"".join(base64.b64decode(c["raw"]) for c in (e.get("children") or []))

out = {}
for page in d["pages"]:
    for e in page.get("entries") or []:
        if e.get("state") != "Written":
            continue
        md = e.get("metadata") or {}
        name = ns_name.get(md.get("namespace"))
        if name not in WANT:
            continue
        t, key = md.get("type"), e.get("key")
        if t == "string":
            raw = children_bytes(e)[: e["data"]["size"]]
            val = {"t": "string", "v": raw.rstrip(b"\x00").decode("utf-8")}
        elif t == "blob_data":
            raw = children_bytes(e)[: e["data"]["size"]]
            val = {"t": "blob", "v": raw.hex()}
        elif t and t.startswith(("uint", "int")):
            val = {"t": t, "v": e["data"]["value"]}
        else:
            continue
        out.setdefault(name, {})[key] = val

print(json.dumps(out, indent=1))
