#!/usr/bin/env python3
"""
Stepik Stats Tracker
Collects daily stats: followers, learners per course, sales per course.
Saves to stepik_stats.json and generates password-protected stepik_report.html
"""

import json
import os
import sys
import base64
import requests
from datetime import datetime, date

# ── Config ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def _require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(f"❌ ERROR: environment variable {name} is not set.")
        print(f"   Set it before running:  export {name}=...")
        sys.exit(1)
    return val

CLIENT_ID     = os.environ.get("STEPIK_CLIENT_ID", "").strip()     or _require_env("STEPIK_CLIENT_ID")
CLIENT_SECRET = os.environ.get("STEPIK_CLIENT_SECRET", "").strip() or _require_env("STEPIK_CLIENT_SECRET")
USER_ID       = 913560008
DATA_FILE     = os.path.join(SCRIPT_DIR, "stepik_stats.json")
REPORT_FILE   = os.path.join(SCRIPT_DIR, "stepik_report.html")

# Dashboard password — used to encrypt both HTML and JSON (required)
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "").strip()

# ── Auth ─────────────────────────────────────────────────────────────────────
def get_token():
    r = requests.post("https://stepik.org/oauth2/token/", data={
        "grant_type":    "client_credentials",
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

# ── Data collection ──────────────────────────────────────────────────────────
def get_user_info(token):
    h = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"https://stepik.org/api/users/{USER_ID}", headers=h, timeout=30)
    r.raise_for_status()
    user = r.json()["users"][0]
    return {
        "followers": user.get("followers_count", 0),
        "knowledge": user.get("knowledge", 0),
    }

def get_courses(token):
    h = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"https://stepik.org/api/courses?owner={USER_ID}&page_size=50", headers=h, timeout=30)
    r.raise_for_status()
    courses = r.json().get("courses", [])
    result = []
    for c in courses:
        result.append({
            "id":       c["id"],
            "title":    c["title"],
            "price":    float(c["price"]) if c.get("price") else 0.0,
            "learners": c.get("learners_count", 0),
            "is_free":  c.get("price") is None or float(c.get("price") or 0) == 0,
        })
    return result

def get_course_payments(token, course_id):
    h = {"Authorization": f"Bearer {token}"}
    payments = []
    page = 1
    while True:
        r = requests.get(
            f"https://stepik.org/api/course-payments?course={course_id}&page={page}&page_size=100",
            headers=h, timeout=30
        )
        if r.status_code != 200:
            break
        data = r.json()
        batch = data.get("course-payments", [])
        payments.extend(batch)
        if not data.get("meta", {}).get("has_next"):
            break
        page += 1
    count   = len(payments)
    revenue = sum(float(p.get("amount", 0)) for p in payments)
    return count, revenue

# ── Crypto helpers ───────────────────────────────────────────────────────────
def _get_crypto():
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return PBKDF2HMAC, hashes, AESGCM
    except ImportError:
        return None, None, None

def _derive_key(password: str, salt: bytes) -> bytes:
    PBKDF2HMAC, hashes, _ = _get_crypto()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(plaintext: bytes, password: str) -> dict:
    """Return dict with salt/iv/ct as base64 strings."""
    _, _, AESGCM = _get_crypto()
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = _derive_key(password, salt)
    ct   = AESGCM(key).encrypt(iv, plaintext, None)
    return {
        "enc":  True,
        "salt": base64.b64encode(salt).decode(),
        "iv":   base64.b64encode(iv).decode(),
        "ct":   base64.b64encode(ct).decode(),
    }

def decrypt_bytes(blob: dict, password: str) -> bytes:
    """Decrypt a dict produced by encrypt_bytes."""
    _, _, AESGCM = _get_crypto()
    salt = base64.b64decode(blob["salt"])
    iv   = base64.b64decode(blob["iv"])
    ct   = base64.b64decode(blob["ct"])
    key  = _derive_key(password, salt)
    return AESGCM(key).decrypt(iv, ct, None)

# ── Persistence ──────────────────────────────────────────────────────────────
def load_data() -> dict:
    if not os.path.exists(DATA_FILE):
        return {"snapshots": []}
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)
    # Encrypted file?
    if raw.get("enc") and DASHBOARD_PASSWORD:
        try:
            plaintext = decrypt_bytes(raw, DASHBOARD_PASSWORD)
            return json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            print(f"❌ Could not decrypt {DATA_FILE}: {e}")
            sys.exit(1)
    return raw

def save_data(data: dict):
    if DASHBOARD_PASSWORD:
        blob = encrypt_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"), DASHBOARD_PASSWORD)
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(blob, f)
        print("  🔐 Data encrypted with DASHBOARD_PASSWORD")
    else:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print("  ⚠  DASHBOARD_PASSWORD not set — data saved unencrypted")

# ── HTML dashboard (inner content) ───────────────────────────────────────────
def generate_inner_html(data):
    snapshots = data["snapshots"]
    if not snapshots:
        return "<html><body><p>No data yet.</p></body></html>"

    snapshots_sorted = sorted(snapshots, key=lambda x: x["date"])
    latest = snapshots_sorted[-1]
    dates  = [s["date"] for s in snapshots_sorted]

    all_courses = {}
    for s in snapshots_sorted:
        for c in s.get("courses", []):
            if c["id"] not in all_courses:
                all_courses[c["id"]] = c["title"]

    followers_series = [s["followers"] for s in snapshots_sorted]

    course_series = {}
    for cid, ctitle in all_courses.items():
        course_series[cid] = {"title": ctitle, "learners": [], "sales": [], "revenue": []}
        for s in snapshots_sorted:
            found = next((c for c in s.get("courses", []) if c["id"] == cid), None)
            course_series[cid]["learners"].append(found["learners"] if found else None)
            course_series[cid]["sales"].append(found.get("sales_count", 0) if found else None)
            course_series[cid]["revenue"].append(found.get("revenue", 0) if found else None)

    colors = ["#4f8ef7", "#f76c4f", "#4fc98e", "#f7c04f", "#9b4ff7", "#4ff7f1"]

    def course_rows_html():
        rows = []
        for cid, cs in course_series.items():
            latest_data = next((c for c in latest.get("courses", []) if c["id"] == cid), {})
            price  = f"{latest_data.get('price', 0):.0f} ₽" if not latest_data.get("is_free") else "Бесплатно"
            sales  = latest_data.get("sales_count", 0)
            rev    = latest_data.get("revenue", 0.0)
            lrn    = latest_data.get("learners", 0)
            title  = cs["title"]
            rows.append(f"""
              <tr>
                <td><a href="https://stepik.org/course/{cid}" target="_blank">{title[:55]}</a></td>
                <td>{price}</td>
                <td class="num">{lrn}</td>
                <td class="num">{sales}</td>
                <td class="num">{rev:,.0f} ₽</td>
              </tr>""")
        return "".join(rows)

    def js_datasets_learners():
        ds = []
        for i, (cid, cs) in enumerate(course_series.items()):
            color = colors[i % len(colors)]
            vals  = json.dumps(cs["learners"])
            label = cs["title"][:40].replace('"', "'")
            ds.append(f"""{{label:"{label}",data:{vals},borderColor:"{color}",backgroundColor:"{color}22",tension:0.3,fill:false}}""")
        return ",\n".join(ds)

    def js_datasets_sales():
        ds = []
        for i, (cid, cs) in enumerate(course_series.items()):
            color = colors[i % len(colors)]
            if all(v == 0 or v is None for v in cs["sales"]):
                continue
            vals  = json.dumps(cs["sales"])
            label = cs["title"][:40].replace('"', "'")
            ds.append(f"""{{label:"{label}",data:{vals},borderColor:"{color}",backgroundColor:"{color}22",tension:0.3,fill:false}}""")
        return ",\n".join(ds)

    total_revenue  = sum(c.get("revenue", 0) for c in latest.get("courses", []))
    total_sales    = sum(c.get("sales_count", 0) for c in latest.get("courses", []))
    total_learners = sum(c.get("learners", 0) for c in latest.get("courses", []))
    followers      = latest.get("followers", 0)
    updated_at     = latest.get("timestamp", latest["date"])

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stepik Dashboard — Максим Мигутин</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f1117; color: #e0e0e0; }}
  header {{ background: #1a1d27; padding: 20px 32px; border-bottom: 1px solid #2a2d3a;
            display: flex; align-items: center; gap: 16px; }}
  header h1 {{ font-size: 20px; font-weight: 600; color: #fff; }}
  header .sub {{ color: #888; font-size: 13px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
               padding: 24px 32px; }}
  .kpi {{ background: #1a1d27; border-radius: 12px; padding: 20px 24px;
          border: 1px solid #2a2d3a; }}
  .kpi .val {{ font-size: 32px; font-weight: 700; color: #4f8ef7; }}
  .kpi .lbl {{ font-size: 13px; color: #888; margin-top: 4px; }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;
             padding: 0 32px 24px; }}
  .chart-box {{ background: #1a1d27; border-radius: 12px; padding: 20px;
                border: 1px solid #2a2d3a; }}
  .chart-box h3 {{ font-size: 14px; color: #aaa; margin-bottom: 16px; }}
  .section {{ padding: 0 32px 32px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d27;
           border-radius: 12px; overflow: hidden; border: 1px solid #2a2d3a; }}
  th {{ background: #22253a; color: #888; font-size: 12px; text-transform: uppercase;
        letter-spacing: .05em; padding: 12px 16px; text-align: left; }}
  td {{ padding: 12px 16px; border-top: 1px solid #2a2d3a; font-size: 14px; }}
  td a {{ color: #4f8ef7; text-decoration: none; }}
  td a:hover {{ text-decoration: underline; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .footer {{ text-align: center; padding: 16px; color: #555; font-size: 12px; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>📊 Stepik Dashboard</h1>
    <div class="sub">Максим Мигутин · обновлено {updated_at}</div>
  </div>
</header>
<div class="kpi-grid">
  <div class="kpi"><div class="val">{followers}</div><div class="lbl">Подписчиков</div></div>
  <div class="kpi"><div class="val">{total_learners}</div><div class="lbl">Всего студентов</div></div>
  <div class="kpi"><div class="val">{total_sales}</div><div class="lbl">Всего продаж</div></div>
  <div class="kpi"><div class="val">{total_revenue:,.0f} ₽</div><div class="lbl">Общий доход</div></div>
</div>
<div class="charts">
  <div class="chart-box"><h3>Подписчики</h3><canvas id="chartFollowers"></canvas></div>
  <div class="chart-box"><h3>Студенты по курсам</h3><canvas id="chartLearners"></canvas></div>
  <div class="chart-box"><h3>Продажи по курсам</h3><canvas id="chartSales"></canvas></div>
</div>
<div class="section">
  <table>
    <thead>
      <tr><th>Курс</th><th>Цена</th><th class="num">Студентов</th><th class="num">Продаж</th><th class="num">Доход</th></tr>
    </thead>
    <tbody>{course_rows_html()}</tbody>
  </table>
</div>
<div class="footer">Данные собраны автоматически · {len(snapshots_sorted)} снапшотов</div>
<script>
const labels = {json.dumps(dates)};
const opts = {{
  responsive: true,
  plugins: {{ legend: {{ labels: {{ color: '#aaa', boxWidth: 12, font: {{ size: 11 }} }} }} }},
  scales: {{
    x: {{ ticks: {{ color: '#666', maxRotation: 45 }}, grid: {{ color: '#2a2d3a' }} }},
    y: {{ ticks: {{ color: '#666' }}, grid: {{ color: '#2a2d3a' }} }}
  }}
}};
new Chart(document.getElementById('chartFollowers'), {{
  type: 'line',
  data: {{ labels, datasets: [{{
    label: 'Подписчики', data: {json.dumps(followers_series)},
    borderColor: '#4f8ef7', backgroundColor: '#4f8ef722', tension: 0.3, fill: true
  }}] }},
  options: opts
}});
new Chart(document.getElementById('chartLearners'), {{
  type: 'line', data: {{ labels, datasets: [{js_datasets_learners()}] }}, options: opts
}});
new Chart(document.getElementById('chartSales'), {{
  type: 'line', data: {{ labels, datasets: [{js_datasets_sales()}] }}, options: opts
}});
</script>
</body>
</html>"""


# ── Encryption ───────────────────────────────────────────────────────────────
def encrypt_to_shell_html(inner_html: str, password: str) -> str:
    """
    Encrypt inner_html with AES-256-GCM (key derived via PBKDF2).
    Returns a standalone HTML page with a password gate and embedded encrypted blob.
    On correct password, the browser decrypts and renders the dashboard.
    """
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("  ⚠ 'cryptography' not installed — saving unencrypted HTML")
        return inner_html

    salt = os.urandom(16)
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    key  = kdf.derive(password.encode("utf-8"))

    iv         = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, inner_html.encode("utf-8"), None)

    salt_b64 = base64.b64encode(salt).decode()
    iv_b64   = base64.b64encode(iv).decode()
    ct_b64   = base64.b64encode(ciphertext).decode()

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stepik Dashboard</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0f1117;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       display:flex;justify-content:center;align-items:center;min-height:100vh}}
  .box{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:16px;padding:40px 48px;
        text-align:center;width:340px}}
  .box h1{{font-size:22px;margin-bottom:8px;color:#fff}}
  .box p{{color:#888;font-size:13px;margin-bottom:28px}}
  input{{width:100%;padding:12px 16px;border-radius:8px;border:1px solid #3a3d4a;
         background:#12141e;color:#fff;font-size:15px;outline:none;transition:.2s}}
  input:focus{{border-color:#4f8ef7}}
  button{{margin-top:12px;width:100%;padding:12px;border-radius:8px;border:none;
          background:#4f8ef7;color:#fff;font-size:15px;cursor:pointer;transition:.15s}}
  button:hover{{background:#3a7ae8}}
  button:active{{transform:scale(.98)}}
  #err{{margin-top:12px;color:#f76c4f;font-size:13px;display:none}}
  #spinner{{margin-top:12px;color:#888;font-size:13px;display:none}}
</style>
</head>
<body>
<div class="box">
  <h1>📊 Stepik Dashboard</h1>
  <p>Введите пароль для просмотра</p>
  <input type="password" id="pwd" placeholder="Пароль" autofocus>
  <button id="btn" onclick="unlock()">Открыть</button>
  <div id="spinner">Расшифровываю...</div>
  <div id="err">Неверный пароль</div>
</div>
<script>
const SALT_B64 = "{salt_b64}";
const IV_B64   = "{iv_b64}";
const CT_B64   = "{ct_b64}";

function b64ToBytes(b64){{
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}}

async function unlock(){{
  const pwd = document.getElementById('pwd').value;
  if(!pwd) return;
  document.getElementById('err').style.display='none';
  document.getElementById('spinner').style.display='block';
  document.getElementById('btn').disabled=true;
  try {{
    const salt = b64ToBytes(SALT_B64);
    const iv   = b64ToBytes(IV_B64);
    const ct   = b64ToBytes(CT_B64);
    const enc  = new TextEncoder();
    const km   = await crypto.subtle.importKey("raw", enc.encode(pwd), "PBKDF2", false, ["deriveKey"]);
    const key  = await crypto.subtle.deriveKey(
      {{name:"PBKDF2", salt, iterations:100000, hash:"SHA-256"}},
      km, {{name:"AES-GCM", length:256}}, false, ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt({{name:"AES-GCM", iv}}, key, ct);
    const html  = new TextDecoder().decode(plain);
    document.open(); document.write(html); document.close();
  }} catch(e) {{
    document.getElementById('spinner').style.display='none';
    document.getElementById('err').style.display='block';
    document.getElementById('btn').disabled=false;
    document.getElementById('pwd').select();
  }}
}}

document.getElementById('pwd').addEventListener('keydown', e => {{
  if(e.key==='Enter') unlock();
}});
</script>
</body>
</html>"""


# ── HTML report ──────────────────────────────────────────────────────────────
def generate_html(data):
    inner = generate_inner_html(data)
    if DASHBOARD_PASSWORD:
        output = encrypt_to_shell_html(inner, DASHBOARD_PASSWORD)
        print("  🔐 HTML encrypted with DASHBOARD_PASSWORD")
    else:
        output = inner
        print("  ⚠  DASHBOARD_PASSWORD not set — HTML is unencrypted")

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(output)


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] Stepik stats collection started")

    token     = get_token()
    user_info = get_user_info(token)
    courses   = get_courses(token)

    for c in courses:
        if not c["is_free"]:
            count, revenue = get_course_payments(token, c["id"])
            c["sales_count"] = count
            c["revenue"]     = revenue
        else:
            c["sales_count"] = 0
            c["revenue"]     = 0.0

    snapshot = {
        "date":      date.today().isoformat(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "followers": user_info["followers"],
        "knowledge": user_info["knowledge"],
        "courses":   courses,
    }

    data = load_data()
    data["snapshots"] = [s for s in data["snapshots"] if s["date"] != snapshot["date"]]
    data["snapshots"].append(snapshot)
    save_data(data)

    print(f"  Followers:      {snapshot['followers']}")
    total_s = sum(c.get("sales_count", 0) for c in courses)
    total_r = sum(c.get("revenue", 0) for c in courses)
    print(f"  Total students: {sum(c['learners'] for c in courses)}")
    print(f"  Total sales:    {total_s}")
    print(f"  Total revenue:  {total_r:,.0f} ₽")
    for c in courses:
        tag = "FREE" if c["is_free"] else f"{c.get('sales_count',0)} sales / {c.get('revenue',0):,.0f} ₽"
        print(f"  [{c['id']}] {c['title'][:45]:<45} | {c['learners']} students | {tag}")

    generate_html(data)
    print(f"  ✅ Report saved: {REPORT_FILE}")
    print(f"  ✅ Data saved:   {DATA_FILE}")

if __name__ == "__main__":
    main()
