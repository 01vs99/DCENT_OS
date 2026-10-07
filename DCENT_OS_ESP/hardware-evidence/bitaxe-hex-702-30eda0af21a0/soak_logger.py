"""Sample the bench Hex Supra's REST API and append one CSV row per minute.

Read-only: issues GET /api/system/info only. Never writes to the device.
"""
import csv, json, os, time, urllib.request

HOST = os.environ.get("DCENTAXE_HOST", "203.0.113.42")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soak-20260903.csv")
FIELDS = ["ts", "uptimeSeconds", "hashRate", "hashRate_10m", "power", "voltage",
          "current", "temp", "vrTemp", "fanrpm", "fan2rpm", "fanspeed",
          "sharesAccepted", "sharesRejected", "bestDiff", "freeHeap"]

new = not os.path.exists(OUT)
with open(OUT, "a", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    if new:
        w.writerow(FIELDS)
        f.flush()
    while True:
        row = [time.strftime("%Y-%m-%dT%H:%M:%S")]
        try:
            with urllib.request.urlopen(f"http://{HOST}/api/system/info", timeout=15) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            row += [d.get(k, "") for k in FIELDS[1:]]
        except Exception as e:
            row += ["ERR: " + str(e)[:80]] + [""] * (len(FIELDS) - 2)
        w.writerow(row)
        f.flush()
        time.sleep(60)
