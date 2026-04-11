#!/usr/bin/env python3
"""
Stepik Stats Tracker
Collects daily stats: followers, learners, sales, ratings per course.
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

# Stepik organic commission rate:
# When a student pays from the catalog/search (no author promo link),
# Stepik takes 40% and the author receives 60%.
# Source: https://support.stepik.org/hc/en-us/articles/360018110654
ORGANIC_AUTHOR_SHARE = 0.60

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
        # Draft detection: Stepik marks unpublished courses with is_enabled=False
        is_published = bool(c.get("is_enabled", True))

        result.append({
            "id":           c["id"],
            "title":        c["title"],
            "price":        float(c["price"]) if c.get("price") else 0.0,
            "learners":     c.get("learners_count", 0),
            "is_free":      c.get("price") is None or float(c.get("price") or 0) == 0,
            "is_published": is_published,
            "cover":        c.get("cover", ""),
            "rating":       0.0,   # filled later via get_course_reviews
            "reviews":      0,     # filled later via get_course_reviews
        })
    return result

def get_course_reviews(token, course_id):
    """Fetch all reviews for a course, return (count, avg_rating)."""
    h = {"Authorization": f"Bearer {token}"}
    scores, page = [], 1
    while True:
        r = requests.get(
            f"https://stepik.org/api/course-reviews?course={course_id}&page={page}&page_size=100",
            headers=h, timeout=30
        )
        if r.status_code != 200:
            break
        data = r.json()
        batch = data.get("course-reviews", [])
        scores.extend(rev["score"] for rev in batch if rev.get("score"))
        if not data.get("meta", {}).get("has_next"):
            break
        page += 1
    count  = len(scores)
    avg    = round(sum(scores) / count, 2) if count else 0.0
    return count, avg

def get_course_payments(token, course_id):
    """Fetch ALL payments for a course (paginated), return count + total gross revenue."""
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
    if raw.get("enc") and DASHBOARD_PASSWORD:
        try:
            plaintext = decrypt_bytes(raw, DASHBOARD_PASSWORD)
            return json.loads(plaintext.decode("utf-8"))
        except Exception:
            print(f"  ⚠  Could not decrypt {DATA_FILE} (wrong password or corrupted). Starting fresh.")
            return {"snapshots": []}
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

# ── Delta helper ─────────────────────────────────────────────────────────────
def compute_delta(snapshots_sorted: list) -> dict:
    """Compare latest vs previous snapshot, return delta dict."""
    if len(snapshots_sorted) < 2:
        return {}
    latest = snapshots_sorted[-1]
    prev   = snapshots_sorted[-2]

    def course_val(snap, cid, key):
        c = next((x for x in snap.get("courses", []) if x["id"] == cid), None)
        return c.get(key, 0) if c else 0

    delta = {
        "followers": latest["followers"] - prev["followers"],
        "learners":  sum(c.get("learners", 0) for c in latest.get("courses", []) if c.get("is_published", True))
                   - sum(c.get("learners", 0) for c in prev.get("courses",   []) if c.get("is_published", True)),
        "sales":     sum(c.get("sales_count", 0) for c in latest.get("courses", []) if c.get("is_published", True))
                   - sum(c.get("sales_count", 0) for c in prev.get("courses",   []) if c.get("is_published", True)),
        "revenue":   sum(c.get("revenue", 0)     for c in latest.get("courses", []) if c.get("is_published", True))
                   - sum(c.get("revenue", 0)     for c in prev.get("courses",   []) if c.get("is_published", True)),
        "courses":   {},
    }
    all_ids = {c["id"] for snap in [latest, prev] for c in snap.get("courses", [])}
    for cid in all_ids:
        delta["courses"][cid] = {
            "learners": course_val(latest, cid, "learners") - course_val(prev, cid, "learners"),
            "sales":    course_val(latest, cid, "sales_count") - course_val(prev, cid, "sales_count"),
            "revenue":  course_val(latest, cid, "revenue")     - course_val(prev, cid, "revenue"),
        }
    return delta

# ── Monthly aggregation helper ───────────────────────────────────────────────
def monthly_course_counts(snapshots_sorted):
    """Return (months_list, counts_list) — last snapshot per month, active course count."""
    by_month = {}
    for s in snapshots_sorted:
        month = s["date"][:7]  # YYYY-MM
        by_month[month] = s   # keep latest for each month
    months = sorted(by_month.keys())
    counts = [
        sum(1 for c in by_month[m].get("courses", []) if c.get("is_published", True))
        for m in months
    ]
    return months, counts

# ── HTML dashboard (inner content) ───────────────────────────────────────────
def generate_inner_html(data):
    snapshots = data["snapshots"]
    if not snapshots:
        return "<html><body><p>No data yet.</p></body></html>"

    snapshots_sorted = sorted(snapshots, key=lambda x: x["date"])
    latest  = snapshots_sorted[-1]
    dates   = [s["date"] for s in snapshots_sorted]
    delta   = compute_delta(snapshots_sorted)

    # Monthly data
    months, monthly_counts = monthly_course_counts(snapshots_sorted)

    # Only published courses
    published_courses = [c for c in latest.get("courses", []) if c.get("is_published", True)]

    # All unique published courses across all snapshots
    all_courses = {}
    for s in snapshots_sorted:
        for c in s.get("courses", []):
            if c.get("is_published", True) and c["id"] not in all_courses:
                all_courses[c["id"]] = c["title"]

    followers_series = [s["followers"] for s in snapshots_sorted]
    colors = ["#4f8ef7", "#f76c4f", "#4fc98e", "#f7c04f", "#9b4ff7", "#4ff7f1"]

    course_series = {}
    for cid, ctitle in all_courses.items():
        course_series[cid] = {"title": ctitle, "learners": [], "revenue": []}
        for s in snapshots_sorted:
            found = next((c for c in s.get("courses", []) if c["id"] == cid and c.get("is_published", True)), None)
            course_series[cid]["learners"].append(found["learners"] if found else None)
            gross = found.get("revenue", 0) if found else 0
            course_series[cid]["revenue"].append(round(gross * ORGANIC_AUTHOR_SHARE, 2))

    # KPI totals
    total_gross    = sum(c.get("revenue", 0)     for c in published_courses)
    total_net      = total_gross * ORGANIC_AUTHOR_SHARE
    total_sales    = sum(c.get("sales_count", 0) for c in published_courses)
    total_learners = sum(c.get("learners", 0)    for c in published_courses)
    followers      = latest.get("followers", 0)
    updated_at     = latest.get("timestamp", latest["date"])

    def delta_badge(val, is_money=False):
        if not delta or val == 0:
            return ""
        if val > 0:
            txt = f"+{val:,.0f} ₽" if is_money else f"+{val}"
            return f'<span class="delta up">▲ {txt}</span>'
        txt = f"{val:,.0f} ₽" if is_money else f"{val}"
        return f'<span class="delta dn">▼ {txt}</span>'

    d_followers = delta_badge(delta.get("followers", 0))
    d_learners  = delta_badge(delta.get("learners",  0))
    d_sales     = delta_badge(delta.get("sales",     0))
    d_revenue   = delta_badge(delta.get("revenue", 0) * ORGANIC_AUTHOR_SHARE, is_money=True)

    def course_rows_html():
        rows = []
        for cid, cs in course_series.items():
            cd     = next((c for c in published_courses if c["id"] == cid), {})
            price  = f"{cd.get('price',0):.0f} ₽" if not cd.get("is_free") else "Бесплатно"
            net    = cd.get("revenue", 0.0) * ORGANIC_AUTHOR_SHARE
            lrn    = cd.get("learners", 0)
            rating = cd.get("rating", 0)
            reviews= cd.get("reviews", 0)
            cd_d   = delta.get("courses", {}).get(cid, {})
            d_lrn  = delta_badge(cd_d.get("learners", 0))
            d_sale = delta_badge(cd_d.get("sales",    0))
            d_net  = delta_badge(cd_d.get("revenue",  0) * ORGANIC_AUTHOR_SHARE, is_money=True)
            stars  = ""
            if rating:
                filled = round(rating)
                stars  = f'<span class="stars" title="{rating}">{"★"*filled}{"☆"*(5-filled)} <small>{rating}</small></span>'
            rows.append(f"""<tr>
                <td><a href="https://stepik.org/course/{cid}" target="_blank">{cs["title"]}</a></td>
                <td>{price}</td>
                <td class="num">{lrn} {d_lrn}</td>
                <td class="num">{stars}{f" {reviews} отз." if reviews else ""}</td>
                <td class="num">{cd.get("sales_count",0)} {d_sale}</td>
                <td class="num">{net:,.0f} ₽ {d_net}</td>
              </tr>""")
        return "".join(rows)

    def js_datasets(series_key):
        ds = []
        for i, (cid, cs) in enumerate(course_series.items()):
            vals  = cs[series_key]
            if all(v == 0 or v is None for v in vals):
                continue
            color = colors[i % len(colors)]
            label = cs["title"][:42].replace('"', "'")
            ds.append(f"""{{label:"{label}",data:{json.dumps(vals)},borderColor:"{color}",backgroundColor:"{color}22",tension:0.3,fill:false,pointRadius:4}}""")
        return ",\n".join(ds)

    # Course catalog cards HTML
    def catalog_cards_html():
        cards = []
        for cd in published_courses:
            cid    = cd["id"]
            title  = cd["title"]
            cover  = cd.get("cover", "")
            lrn    = cd.get("learners", 0)
            rating = cd.get("rating", 0)
            reviews= cd.get("reviews", 0)
            price  = f"{cd.get('price',0):.0f} ₽" if not cd.get("is_free") else "Бесплатно"
            stars  = f'{"★" * round(rating)}{"☆" * (5 - round(rating))} {rating}' if rating else ""
            img    = f'<img src="{cover}" alt="" onerror="this.style.display=\'none\'">' if cover else '<div class="no-cover"></div>'
            cards.append(f"""<a class="course-card" href="https://stepik.org/course/{cid}" target="_blank">
              <div class="course-thumb">{img}</div>
              <div class="course-info">
                <div class="course-title">{title}</div>
                <div class="course-meta">
                  <span>{lrn} студ.</span>
                  {f'<span class="stars-sm">{stars}</span>' if stars else ""}
                  {f'<span>{reviews} отз.</span>' if reviews else ""}
                  <span class="price-tag">{price}</span>
                </div>
              </div>
            </a>""")
        return "\n".join(cards)

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stepik Dashboard — Максим Мигутин</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e0e0e0}}
header{{background:#1a1d27;padding:20px 32px;border-bottom:1px solid #2a2d3a;display:flex;align-items:center;gap:16px}}
header h1{{font-size:20px;font-weight:600;color:#fff}}
header .sub{{color:#888;font-size:13px}}
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:24px 32px}}
.kpi{{background:#1a1d27;border-radius:12px;padding:20px 24px;border:1px solid #2a2d3a}}
.kpi .val{{font-size:30px;font-weight:700;color:#4f8ef7;display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.kpi .lbl{{font-size:13px;color:#888;margin-top:4px}}
.kpi .hint{{font-size:11px;color:#555;margin-top:2px}}
.charts{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;padding:0 32px 0}}
.charts-bottom{{display:grid;grid-template-columns:1fr;gap:16px;padding:16px 32px 24px}}
.chart-box{{background:#1a1d27;border-radius:12px;padding:20px;border:1px solid #2a2d3a;position:relative}}
.chart-box .chart-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}}
.chart-box h3{{font-size:14px;color:#aaa;margin:0}}
.expand-btn{{background:none;border:1px solid #3a3d4a;border-radius:6px;color:#888;cursor:pointer;
             font-size:13px;padding:3px 8px;transition:.15s;line-height:1}}
.expand-btn:hover{{border-color:#4f8ef7;color:#4f8ef7}}
.section{{padding:0 32px 32px}}
.section-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}}
.section-header h2{{font-size:15px;font-weight:600;color:#ccc}}
table{{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:12px;overflow:hidden;border:1px solid #2a2d3a}}
th{{background:#22253a;color:#888;font-size:12px;text-transform:uppercase;letter-spacing:.05em;padding:12px 16px;text-align:left}}
td{{padding:12px 16px;border-top:1px solid #2a2d3a;font-size:14px}}
td a{{color:#4f8ef7;text-decoration:none}}
td a:hover{{text-decoration:underline}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
.delta{{font-size:11px;font-weight:600;padding:2px 6px;border-radius:4px;margin-left:4px;white-space:nowrap}}
.delta.up{{color:#4fc98e;background:#4fc98e18}}
.delta.dn{{color:#f76c4f;background:#f76c4f18}}
.stars{{color:#f7c04f;font-size:13px}}
.stars small{{color:#888;font-size:11px}}
.stars-sm{{color:#f7c04f;font-size:11px}}
/* Course catalog */
.catalog-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;margin-top:4px}}
.course-card{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:12px;overflow:hidden;
              text-decoration:none;color:inherit;transition:.15s;display:flex;flex-direction:column}}
.course-card:hover{{border-color:#4f8ef7;transform:translateY(-2px)}}
.course-thumb{{height:130px;overflow:hidden;background:#12141e;display:flex;align-items:center;justify-content:center}}
.course-thumb img{{width:100%;height:100%;object-fit:cover}}
.no-cover{{width:100%;height:100%;background:linear-gradient(135deg,#1e2236,#2a2d4a)}}
.course-info{{padding:14px}}
.course-title{{font-size:13px;font-weight:600;color:#e0e0e0;line-height:1.4;margin-bottom:8px}}
.course-meta{{display:flex;flex-wrap:wrap;gap:8px;font-size:12px;color:#666;align-items:center}}
.price-tag{{background:#4f8ef718;color:#4f8ef7;padding:2px 7px;border-radius:4px;font-weight:600}}
/* Modal */
.modal{{display:none;position:fixed;inset:0;background:#000000cc;z-index:1000;
        align-items:center;justify-content:center;padding:24px}}
.modal-inner{{background:#1a1d27;border-radius:16px;border:1px solid #2a2d3a;
              width:min(1100px,96vw);max-height:90vh;display:flex;flex-direction:column;overflow:hidden}}
.modal-top{{display:flex;justify-content:space-between;align-items:center;
            padding:18px 24px;border-bottom:1px solid #2a2d3a}}
.modal-top h2{{font-size:16px;color:#fff}}
.modal-close{{background:none;border:1px solid #3a3d4a;border-radius:8px;color:#aaa;
               cursor:pointer;font-size:16px;padding:4px 12px;transition:.15s}}
.modal-close:hover{{border-color:#f76c4f;color:#f76c4f}}
.modal-body{{padding:24px;flex:1;min-height:0;position:relative}}
.toggle-btn{{background:#22253a;border:1px solid #3a3d4a;border-radius:8px;color:#aaa;
             cursor:pointer;font-size:13px;padding:8px 16px;transition:.15s}}
.toggle-btn:hover{{border-color:#4f8ef7;color:#4f8ef7}}
.footer{{text-align:center;padding:16px;color:#555;font-size:12px}}
</style>
</head>
<body>

<!-- Expand Modal -->
<div class="modal" id="chartModal" onclick="if(event.target===this)closeModal()">
  <div class="modal-inner">
    <div class="modal-top">
      <h2 id="modalTitle"></h2>
      <button class="modal-close" onclick="closeModal()">✕ Закрыть</button>
    </div>
    <div class="modal-body">
      <canvas id="modalCanvas"></canvas>
    </div>
  </div>
</div>

<header>
  <div>
    <h1>📊 Stepik Dashboard</h1>
    <div class="sub">Максим Мигутин · обновлено {updated_at}</div>
  </div>
</header>

<div class="kpi-grid">
  <div class="kpi"><div class="val">{followers} {d_followers}</div><div class="lbl">Подписчиков</div></div>
  <div class="kpi"><div class="val">{total_learners} {d_learners}</div><div class="lbl">Всего студентов</div></div>
  <div class="kpi"><div class="val">{total_sales} {d_sales}</div><div class="lbl">Всего продаж</div></div>
  <div class="kpi">
    <div class="val">{total_net:,.0f} ₽ {d_revenue}</div>
    <div class="lbl">Доход (чистый)</div>
    <div class="hint">после комиссии Stepik 40% · органика</div>
  </div>
</div>

<div class="charts">
  <div class="chart-box">
    <div class="chart-header"><h3>Подписчики</h3></div>
    <canvas id="chartFollowers"></canvas>
  </div>
  <div class="chart-box">
    <div class="chart-header">
      <h3>Студенты по курсам</h3>
      <button class="expand-btn" onclick="expandChart('learners','Студенты по курсам')">⛶ развернуть</button>
    </div>
    <canvas id="chartLearners"></canvas>
  </div>
  <div class="chart-box">
    <div class="chart-header">
      <h3>Чистый доход ₽ по курсам</h3>
      <button class="expand-btn" onclick="expandChart('revenue','Чистый доход ₽ по курсам')">⛶ развернуть</button>
    </div>
    <canvas id="chartRevenue"></canvas>
  </div>
</div>

<div class="charts-bottom">
  <div class="chart-box">
    <div class="chart-header"><h3>Активных курсов в месяц</h3></div>
    <canvas id="chartMonthly" style="max-height:160px"></canvas>
  </div>
</div>

<div class="section">
  <table>
    <thead>
      <tr>
        <th>Курс</th><th>Цена</th>
        <th class="num">Студентов</th>
        <th class="num">Рейтинг / Отзывы</th>
        <th class="num">Продаж</th>
        <th class="num">Доход (чистый)</th>
      </tr>
    </thead>
    <tbody>{course_rows_html()}</tbody>
  </table>
  <div style="margin-top:8px;color:#555;font-size:12px;text-align:right">
    * Чистый доход = сумма продаж × 60% (органические, без промоссылки)
  </div>
</div>

<!-- Course Catalog -->
<div class="section">
  <div class="section-header">
    <h2>📚 Все курсы</h2>
    <button class="toggle-btn" id="catalogToggle" onclick="toggleCatalog()">Показать курсы ▾</button>
  </div>
  <div id="catalogGrid" style="display:none">
    <div class="catalog-grid">
      {catalog_cards_html()}
    </div>
  </div>
</div>

<div class="footer">Данные собраны автоматически · {len(snapshots_sorted)} снапшотов</div>

<script>
const LABELS = {json.dumps(dates)};
const baseOpts = {{
  responsive:true,
  plugins:{{legend:{{labels:{{color:'#aaa',boxWidth:12,font:{{size:11}}}}}}}},
  scales:{{
    x:{{ticks:{{color:'#666',maxRotation:45}},grid:{{color:'#2a2d3a'}}}},
    y:{{ticks:{{color:'#666'}},grid:{{color:'#2a2d3a'}}}}
  }}
}};

// ── Chart configs (stored so we can re-render in modal) ──
const CHART_CONFIGS = {{
  followers: {{
    type:'line',
    data:{{labels:LABELS, datasets:[{{
      label:'Подписчики', data:{json.dumps(followers_series)},
      borderColor:'#4f8ef7',backgroundColor:'#4f8ef722',tension:0.3,fill:true,pointRadius:4
    }}]}},
    options:baseOpts
  }},
  learners: {{
    type:'line',
    data:{{labels:LABELS, datasets:[{js_datasets("learners")}]}},
    options:baseOpts
  }},
  revenue: {{
    type:'line',
    data:{{labels:LABELS, datasets:[{js_datasets("revenue")}]}},
    options:baseOpts
  }}
}};

// Render main charts
new Chart(document.getElementById('chartFollowers'), JSON.parse(JSON.stringify(CHART_CONFIGS.followers)));
new Chart(document.getElementById('chartLearners'),  JSON.parse(JSON.stringify(CHART_CONFIGS.learners)));
new Chart(document.getElementById('chartRevenue'),   JSON.parse(JSON.stringify(CHART_CONFIGS.revenue)));

// Monthly active courses bar chart
new Chart(document.getElementById('chartMonthly'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(months)},
    datasets: [{{
      label: 'Активных курсов',
      data: {json.dumps(monthly_counts)},
      backgroundColor: '#4f8ef7aa',
      borderColor: '#4f8ef7',
      borderRadius: 6,
      borderWidth: 1
    }}]
  }},
  options: {{
    responsive:true,
    plugins:{{legend:{{display:false}}}},
    scales:{{
      x:{{ticks:{{color:'#666'}},grid:{{color:'#2a2d3a'}}}},
      y:{{ticks:{{color:'#666',stepSize:1}},grid:{{color:'#2a2d3a'}},min:0}}
    }}
  }}
}});

// ── Modal expand ──
let _modalChart = null;

function expandChart(key, title) {{
  if (_modalChart) {{ _modalChart.destroy(); _modalChart = null; }}
  document.getElementById('modalTitle').textContent = title;
  document.getElementById('chartModal').style.display = 'flex';
  const ctx = document.getElementById('modalCanvas').getContext('2d');
  const cfg = JSON.parse(JSON.stringify(CHART_CONFIGS[key]));
  // Larger points & font in modal
  if (cfg.options.plugins && cfg.options.plugins.legend)
    cfg.options.plugins.legend.labels.font = {{size:13}};
  (cfg.data.datasets || []).forEach(ds => {{ ds.pointRadius = 5; }});
  _modalChart = new Chart(ctx, cfg);
}}

function closeModal() {{
  document.getElementById('chartModal').style.display = 'none';
  if (_modalChart) {{ _modalChart.destroy(); _modalChart = null; }}
}}

document.addEventListener('keydown', e => {{ if(e.key==='Escape') closeModal(); }});

// ── Course catalog toggle ──
function toggleCatalog() {{
  const grid = document.getElementById('catalogGrid');
  const btn  = document.getElementById('catalogToggle');
  if (grid.style.display === 'none') {{
    grid.style.display = 'block';
    btn.textContent = 'Скрыть курсы ▴';
  }} else {{
    grid.style.display = 'none';
    btn.textContent = 'Показать курсы ▾';
  }}
}}
</script>
</body>
</html>"""


# ── Encryption wrapper ───────────────────────────────────────────────────────
def encrypt_to_shell_html(inner_html: str, password: str) -> str:
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
    iv   = os.urandom(12)
    ct   = AESGCM(key).encrypt(iv, inner_html.encode("utf-8"), None)

    salt_b64 = base64.b64encode(salt).decode()
    iv_b64   = base64.b64encode(iv).decode()
    ct_b64   = base64.b64encode(ct).decode()

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
const SALT_B64="{salt_b64}";
const IV_B64="{iv_b64}";
const CT_B64="{ct_b64}";

function b64ToBytes(b64){{return Uint8Array.from(atob(b64),c=>c.charCodeAt(0));}}

async function unlock(){{
  const pwd=document.getElementById('pwd').value;
  if(!pwd)return;
  document.getElementById('err').style.display='none';
  document.getElementById('spinner').style.display='block';
  document.getElementById('btn').disabled=true;
  try{{
    const salt=b64ToBytes(SALT_B64),iv=b64ToBytes(IV_B64),ct=b64ToBytes(CT_B64);
    const enc=new TextEncoder();
    const km=await crypto.subtle.importKey("raw",enc.encode(pwd),"PBKDF2",false,["deriveKey"]);
    const key=await crypto.subtle.deriveKey(
      {{name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"}},
      km,{{name:"AES-GCM",length:256}},false,["decrypt"]);
    const plain=await crypto.subtle.decrypt({{name:"AES-GCM",iv}},key,ct);
    const html=new TextDecoder().decode(plain);
    document.open();document.write(html);document.close();
  }}catch(e){{
    document.getElementById('spinner').style.display='none';
    document.getElementById('err').style.display='block';
    document.getElementById('btn').disabled=false;
    document.getElementById('pwd').select();
  }}
}}
document.getElementById('pwd').addEventListener('keydown',e=>{{if(e.key==='Enter')unlock();}});
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
        if c["is_published"]:
            # Reviews & rating (all published courses)
            rev_count, avg_rating = get_course_reviews(token, c["id"])
            c["reviews"] = rev_count
            c["rating"]  = avg_rating

            # Payments (paid courses only)
            if not c["is_free"]:
                count, revenue = get_course_payments(token, c["id"])
                c["sales_count"] = count
                c["revenue"]     = revenue
            else:
                c["sales_count"] = 0
                c["revenue"]     = 0.0
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

    # Summary (published only)
    pub = [c for c in courses if c.get("is_published", True)]
    total_s    = sum(c.get("sales_count", 0) for c in pub)
    total_r    = sum(c.get("revenue", 0) for c in pub)
    total_net  = total_r * ORGANIC_AUTHOR_SHARE
    print(f"  Followers:      {snapshot['followers']}")
    print(f"  Total students: {sum(c['learners'] for c in pub)}")
    print(f"  Total sales:    {total_s}")
    print(f"  Gross revenue:  {total_r:,.0f} ₽")
    print(f"  Net revenue:    {total_net:,.0f} ₽  (×{ORGANIC_AUTHOR_SHARE} organic share)")
    for c in courses:
        draft_tag = " [DRAFT — skipped]" if not c.get("is_published", True) else ""
        if c["is_free"] or not c.get("is_published", True):
            tag = f"FREE{draft_tag}"
        else:
            net = c.get('revenue', 0) * ORGANIC_AUTHOR_SHARE
            tag = f"{c.get('sales_count',0)} sales / gross {c.get('revenue',0):,.0f} ₽ / net {net:,.0f} ₽"
        rating_str = f" ★{c.get('rating',0)}" if c.get('rating') else ""
        print(f"  [{c['id']}] {c['title'][:45]:<45} | {c['learners']} students{rating_str} | {tag}")

    generate_html(data)
    print(f"  ✅ Report:  {REPORT_FILE}")
    print(f"  ✅ Data:    {DATA_FILE}")

if __name__ == "__main__":
    main()
