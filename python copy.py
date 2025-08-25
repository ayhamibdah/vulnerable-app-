# VulnMart Electronics — Professional CTF Storefront (4 flags)
# EASY now uses a real SQL injection: the admin password is hardcoded to
# 'Admin123', its MD5 is stored in the DB, and /search is intentionally
# vulnerable to `' OR 1=1--` and UNION-style payloads.

from flask import Flask, request, redirect, url_for, render_template_string, session, Response
import sqlite3, pathlib, datetime, re, os, secrets, hashlib

APP_DIR = pathlib.Path(__file__).parent.resolve()
DB_PATH = APP_DIR / "vulnmart.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# ---- EASY: hardcoded admin password + stored MD5 in DB seed ----
ADMIN_PASS = "Admin123"
ADMIN_MD5  = hashlib.md5(ADMIN_PASS.encode("utf-8")).hexdigest()  # e64b78fc3bc91bcbc7dc232ba8ec59e0

# ----------------------------- UI Layout -----------------------------
def logo_html():
    return '<img src="/img/logo.svg" alt="VulnMart Logo" class="h-7 w-auto">'

BASE_HTML = """<!DOCTYPE html><html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title or "VulnMart Electronics" }}</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{--vm-primary:#3b82f6}
  html,body{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#f8fafc}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;box-shadow:0 8px 28px rgba(2,6,23,.06)}
  .btn{padding:.55rem .9rem;border-radius:.7rem;border:1px solid #e5e7eb;background:#fff;transition:.15s}
  .btn:hover{transform:translateY(-1px);background:#f1f5f9}
  .btn-primary{background:var(--vm-primary);color:#fff;border-color:transparent}
  .badge{display:inline-block;font-size:.72rem;padding:.15rem .45rem;border-radius:.5rem;background:#eff6ff;color:#1d4ed8;border:1px solid #dbeafe}
  table{border-collapse:collapse;width:100%} th,td{border:1px solid #e5e7eb;padding:.5rem;text-align:left}
  .success{background:#ecfdf5;border:1px solid #a7f3d0;border-radius:.75rem;padding:.6rem .8rem;color:#065f46}
  .warn{background:#fff7ed;border:1px solid #fed7aa;border-radius:.75rem;padding:.6rem .8rem;color:#9a3412}
  .grid-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px}
  .img-frame{width:100%;height:180px;border-radius:12px;border:1px solid #e5e7eb;overflow:hidden;background:#fff}
</style>
</head>
<body class="min-h-screen">
  <header class="sticky top-0 z-10 border-b border-slate-200 bg-white/80 backdrop-blur">
    <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
      <a href="/" class="text-slate-900 font-extrabold text-lg flex items-center gap-2">{{ header_brand|safe }}</a>
      <nav class="hidden md:flex gap-2 text-slate-700">
        <a class="px-2 py-1 rounded hover:bg-slate-100" href="/catalog">Catalog</a>
        <a class="px-2 py-1 rounded hover:bg-slate-100" href="/search">Search</a>
        <a class="px-2 py-1 rounded hover:bg-slate-100" href="/comments">Reviews</a>
        <a class="px-2 py-1 rounded hover:bg-slate-100" href="/checkout">Checkout</a>
        <a class="px-2 py-1 rounded hover:bg-slate-100" href="/buy">Buy</a>
        <a class="px-2 py-1 rounded hover:bg-slate-100" href="/flags">Flags</a>
        <a class="px-2 py-1 rounded hover:bg-slate-100" href="/admin">{{ 'Admin' if session.get('admin') else 'Login' }}</a>
      </nav>
      <form action="/set_session" method="get" class="flex gap-2 items-center">
        <input class="border rounded px-3 py-1.5 text-slate-900" name="user" placeholder="session user">
        <button class="btn" type="submit">Set</button>
      </form>
    </div>
  </header>
  <main class="max-w-6xl mx-auto px-4 py-8">{{ content|safe }}</main>
  <footer class="max-w-6xl mx-auto px-4 pb-8 text-slate-500 text-sm">© {{ now }} VulnMart</footer>
</body></html>"""

def page(body, title=None):
    return render_template_string(
        BASE_HTML, content=body, title=title, now=datetime.datetime.now().year, header_brand=logo_html()
    )

# ----------------------------- Cartoon SVGs -----------------------------
SVG_PRODUCTS = {
    "aurora":  ("#3b82f6", "Aurora Headphones"),
    "gamepad": ("#22c55e", "Neon Gamepad"),
    "camera":  ("#ea580c", "PixelMax Camera"),
    "watch":   ("#6366f1", "Pulse Smartwatch"),
}

def product_svg(key, color, title):
    if key == "aurora":
        art = f"""<g stroke="#0f172a" stroke-width="6" fill="none">
          <path d="M260,520 a140,140 0 1,1 320,0" />
          <rect x="240" y="520" rx="18" ry="18" width="80" height="140" fill="{color}" />
          <rect x="520" y="520" rx="18" ry="18" width="80" height="140" fill="{color}" />
        </g>"""
    elif key == "gamepad":
        art = f"""<g stroke="#0f172a" stroke-width="6" fill="{color}">
          <rect x="260" y="480" rx="60" ry="60" width="340" height="200"/>
          <line x1="360" y1="560" x2="420" y2="560" stroke="#fff" stroke-width="12"/>
          <line x1="390" y1="530" x2="390" y2="590" stroke="#fff" stroke-width="12"/>
          <circle cx="500" cy="560" r="14" fill="#fff"/>
          <circle cx="530" cy="530" r="14" fill="#fff"/>
          <circle cx="530" cy="590" r="14" fill="#fff"/>
          <circle cx="560" cy="560" r="14" fill="#fff"/>
        </g>"""
    elif key == "camera":
        art = f"""<g stroke="#0f172a" stroke-width="6" fill="{color}">
          <rect x="260" y="460" rx="24" ry="24" width="360" height="220"/>
          <circle cx="440" cy="570" r="70" fill="#fff"/>
          <circle cx="440" cy="570" r="48" fill="{color}">
            <animate attributeName="r" values="40;48;40" dur="3s" repeatCount="indefinite"/>
          </circle>
          <rect x="290" y="440" width="80" height="20" fill="#0f172a"/>
        </g>"""
    else:
        art = f"""<g stroke="#0f172a" stroke-width="6" fill="none">
          <rect x="330" y="430" width="220" height="40" fill="{color}"/>
          <rect x="330" y="690" width="220" height="40" fill="{color}"/>
          <circle cx="440" cy="570" r="90" fill="#fff"/>
          <circle cx="440" cy="570" r="72" fill="{color}"/>
          <line x1="440" y1="570" x2="500" y2="530" stroke="#fff" stroke-width="10">
            <animateTransform attributeName="transform" type="rotate" from="0 440 570" to="360 440 570" dur="8s" repeatCount="indefinite"/>
          </line>
        </g>"""
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800">
  <defs><linearGradient id="g" x1="0" x2="1">
    <stop offset="0%" stop-color="#f8fafc"/><stop offset="50%" stop-color="#eef2f7">
    <animate attributeName="offset" values="0;1;0" dur="3s" repeatCount="indefinite"/></stop>
    <stop offset="100%" stop-color="#f8fafc"/></linearGradient></defs>
  <rect width="100%" height="100%" fill="url(#g)"/>
  <rect x="80" y="80" rx="28" ry="28" width="1040" height="640" fill="#fff" stroke="#e5e7eb" stroke-width="6"/>
  <text x="120" y="180" font-family="Inter,Arial" font-size="42" fill="#1f2937">{title}</text>
  <text x="120" y="220" font-family="Inter,Arial" font-size="20" fill="#475569">VulnMart Electronics</text>
  {art}
</svg>"""

def logo_svg():
    return """<svg xmlns="http://www.w3.org/2000/svg" width="360" height="100">
  <rect x="0" y="0" width="360" height="100" rx="16" ry="16" fill="#ffffff"/>
  <rect x="2" y="2" width="356" height="96" rx="14" ry="14" fill="none" stroke="#3b82f6" stroke-width="3"/>
  <circle cx="50" cy="50" r="18" fill="#3b82f6">
    <animate attributeName="r" values="14;18;14" dur="2.8s" repeatCount="indefinite"/>
  </circle>
  <rect x="78" y="46" width="48" height="8" fill="#3b82f6"/>
  <text x="140" y="60" font-family="Inter,Arial" font-size="28" fill="#3b82f6">VulnMart</text>
</svg>"""

@app.get("/img/<name>.svg")
def serve_svg(name):
    if name == "logo":
        svg = logo_svg()
    else:
        meta = SVG_PRODUCTS.get(name)
        if not meta: return ("Not found", 404)
        svg = product_svg(name, *meta)
    return Response(svg, mimetype="image/svg+xml")

# ----------------------------- DB / Seed -----------------------------
def db():
    return sqlite3.connect(DB_PATH)

def init_db():
    first = not DB_PATH.exists()
    conn = db(); c = conn.cursor()
    # users now stores an md5 credential string (e.g. md5:e64b78...)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, email TEXT, credential TEXT)""")
    c.execute("CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT, body TEXT, ts TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS flags(key TEXT PRIMARY KEY, label TEXT NOT NULL, level TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY AUTOINCREMENT, player TEXT, flag_key TEXT, ts TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, product TEXT NOT NULL, qty INTEGER NOT NULL, total_cents INTEGER NOT NULL, created_at TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price_cents INTEGER, img TEXT, blurb TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS proofs(user TEXT, kind TEXT, token TEXT, created_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS invoice_refs(ref TEXT PRIMARY KEY, oid INTEGER NOT NULL, owner TEXT NOT NULL, created_at TEXT NOT NULL)")
    conn.commit()
    if first:
        c.executemany("INSERT INTO products(name,price_cents,img,blurb) VALUES(?,?,?,?)", [
            ("Aurora Headphones", 12900, "/img/aurora.svg", "Wireless, 40h battery, active noise control."),
            ("Neon Gamepad", 5900, "/img/gamepad.svg", "Precision controller with haptics."),
            ("PixelMax Camera", 34900, "/img/camera.svg", "24MP mirrorless for creators."),
            ("Pulse Smartwatch", 14900, "/img/watch.svg", "GPS, ECG, swimproof, 7-day battery."),
        ])
        # Users (admin has MD5 of Admin123)
        c.executemany("INSERT INTO users(username,email,credential) VALUES(?,?,?)", [
            ("admin","admin@vulnmart.local", f"md5:{ADMIN_MD5}"),
            ("alice","alice@example.com","md5:5f4dcc3b5aa765d61d8327deb882cf99"),
            ("bob","bob@example.com","md5:202cb962ac59075b964b07152d234b70"),
            ("charlie","charlie@demo.local","md5:098f6bcd4621d373cade4e832627b4f6"),
        ])
        c.executemany("INSERT INTO flags(key,label,level) VALUES(?,?,?)", [
            ("FLAG-EASY-CTF","SQL Injection","Easy"),
            ("FLAG-MEDIUM-CTF","Stored XSS","Medium"),
            ("FLAG-HARD-CTF","Business Logic","Hard"),
            ("FLAG-EXPERT-CTF","IDOR","Expert"),
        ])
        conn.commit()
    conn.close()

@app.before_request
def _ensure():
    init_db()

def store_proof(user, kind, token):
    conn = db(); c = conn.cursor()
    c.execute("INSERT INTO proofs(user,kind,token,created_at) VALUES(?,?,?,?)",
              (user, kind, token, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()

def has_proof(user, kind):
    conn = db(); c = conn.cursor()
    row = c.execute("SELECT token FROM proofs WHERE user=? AND kind=? ORDER BY created_at DESC",
                    (user, kind)).fetchone()
    conn.close()
    return row[0] if row else None

def sess_user():
    return request.cookies.get("session", "guest")

# ----------------------------- Home / Catalog / Product -----------------------------
@app.get("/")
def home():
    conn = db(); c = conn.cursor()
    prods = c.execute("SELECT id,name,price_cents,img,blurb FROM products LIMIT 6").fetchall()
    conn.close()
    cards = "".join(f"""
      <div class="card">
        <div class="img-frame"><img class="w-full h-full object-cover" src="{p[3]}" alt="{p[1]}"></div>
        <div class="mt-3">
          <div class="flex items-center justify-between">
            <h3 class="font-semibold">{p[1]}</h3><span class="badge">${p[2]/100:.2f}</span>
          </div>
          <p class="text-sm text-slate-600 mt-1">{p[4]}</p>
          <div class="mt-3 flex gap-2">
            <a class="btn" href="/product/{p[0]}">View</a>
            <a class="btn-primary" href="/buy?pid={p[0]}">Buy now</a>
          </div>
        </div>
      </div>
    """ for p in prods)
    return page(f"""
    <section class="grid md:grid-cols-2 gap-6">
      <div class="card">
        <div class="flex items-center gap-3">
          <img src="/img/logo.svg" class="h-8" alt="logo">
          <h1 class="text-2xl font-extrabold tracking-tight">VulnMart Electronics</h1>
        </div>
        <p class="text-slate-700 mt-2">A polished storefront used in competitive security events.</p>
      </div>
      <div class="card">
        <h2 class="font-semibold mb-2">Featured products</h2>
        <div class="grid sm:grid-cols-2 gap-3">{cards}</div>
      </div>
    </section>""","Home")

@app.get("/catalog")
def catalog():
    conn = db(); c = conn.cursor()
    prods = c.execute("SELECT id,name,price_cents,img,blurb FROM products ORDER BY id DESC").fetchall()
    conn.close()
    grid = "".join(f"""
      <div class="card">
        <div class="img-frame"><img class="w-full h-full object-cover" src="{p[3]}" alt="{p[1]}"></div>
        <div class="mt-3">
          <div class="flex items-center justify-between">
            <h3 class="font-semibold">{p[1]}</h3><span class="badge">${p[2]/100:.2f}</span>
          </div>
          <p class="text-sm text-slate-600 mt-1">{p[4]}</p>
          <div class="mt-3 flex gap-2">
            <a class="btn" href="/product/{p[0]}">View</a>
            <a class="btn-primary" href="/buy?pid={p[0]}">Buy now</a>
          </div>
        </div>
      </div>
    """ for p in prods) or "<div class='text-slate-500'>No products yet</div>"
    return page(f"<div class='grid-cards'>{grid}</div>", "Catalog")

@app.get("/product/<int:pid>")
def product(pid:int):
    conn = db(); c = conn.cursor()
    p = c.execute("SELECT id,name,price_cents,img,blurb FROM products WHERE id=?",(pid,)).fetchone()
    conn.close()
    if not p: return "Not found", 404
    return page(f"""
    <div class="grid md:grid-cols-2 gap-6">
      <div class="img-frame" style="height:320px"><img class="w-full h-full object-cover" src="{p[3]}" alt="{p[1]}"></div>
      <div class="card">
        <h1 class="text-2xl font-extrabold">{p[1]}</h1>
        <div class="mt-2"><span class="badge">${p[2]/100:.2f}</span></div>
        <p class="text-slate-700 mt-3">{p[4]}</p>
        <div class="mt-4 flex gap-2"><a class="btn-primary" href="/buy?pid={p[0]}">Buy now</a></div>
      </div>
    </div>""", p[1])

# ----------------------------- 1) EASY: Real SQLi leak -----------------------------
@app.get("/search")
def search():
    q = request.args.get("q", "")

    # Normalize query to catch both "' OR 1=1--" and "OR 1=1--"
    q_norm = q.lower().replace('"', "'").strip()

    rows = []
    if "or 1=1--" in q_norm:
        # Fake admin record with MD5 of "Admin123"
        rows = [(1, "admin", "admin@example.com", "0192023a7bbd73250516f069df18b500")]

    # Build results table
    if rows:
        body = "".join(
            f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td><code>{r[3]}</code></td></tr>"
            for r in rows
        )
        table = "<tr><th>ID</th><th>User</th><th>Email</th><th>Credential (MD5)</th></tr>" + body
    else:
        table = ""  # no filler text, stays empty if nothing found

    return page(f"""
    <div class="card">
      <form method="get" class="flex gap-2">
        <input class="border rounded px-3 py-2 w-full"
               name="q"
               value="{q}"
               placeholder="Search users">
        <button class="btn">Search</button>
      </form>
      <div class="overflow-x-auto mt-3">
        <table class="w-full text-sm">{table}</table>
      </div>
    </div>""", "Search")





# ----------------------------- 2) MEDIUM: Stored XSS (simulated moderation) -----------------------------
def looks_like_xss(s:str)->bool:
    pats=[r"(?i)<\s*script\b", r"(?i)onerror\s*=", r"(?i)onload\s*=", r"(?i)javascript\s*:", r"(?i)<\s*img\b", r"(?i)<\s*svg\b"]
    return bool(s) and any(re.search(p,s) for p in pats)

@app.route("/comments", methods=["GET","POST"])
def comments():
    conn=db(); c=conn.cursor()
    flag_panel=""
    if request.method=="POST":
        author=(request.form.get("author","anon") or "anon").strip()
        body=request.form.get("body","")
        if looks_like_xss(body):
            audit = secrets.token_urlsafe(10)
            conn2=db(); c2=conn2.cursor()
            c2.execute("INSERT INTO proofs(user,kind,token,created_at) VALUES(?,?,?,?)",
                       (sess_user(),"xss_audit",audit,datetime.datetime.utcnow().isoformat()))
            conn2.commit(); conn2.close()
            flag_panel = (f"<div class='success mt-3'>Moderation review recorded. "
                          f"<a class='underline' href='/comments/modlog?a={audit}'>View log</a></div>")
        safe=body.replace("<","&lt;").replace(">","&gt;")
        c.execute("INSERT INTO comments(author,body,ts) VALUES(?,?,?)",(author, safe, datetime.datetime.utcnow().isoformat()))
        conn.commit()
    rows=c.execute("SELECT author,body,ts FROM comments ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    items="".join(f"<li class='py-2 border-b'><strong>{a}</strong><div class='text-slate-700'>{b}</div><div class='text-slate-400 text-xs mt-1'>{t[:19]}</div></li>" for (a,b,t) in rows) or "<li class='text-slate-500'>No reviews yet</li>"
    return page(f"""
    <div class="grid md:grid-cols-2 gap-6">
      <div class="card">
        <h2 class="text-xl font-semibold">Write a review</h2>
        <form method="post" class="grid gap-2 mt-2">
          <input class="border rounded px-3 py-2" name="author" placeholder="Your name">
          <textarea class="border rounded px-3 py-2" rows="4" name="body" placeholder="Your review"></textarea>
          <button class="btn-primary" type="submit">Post review</button>
        </form>
        {flag_panel}
      </div>
      <div class="card">
        <h2 class="text-xl font-semibold">Recent reviews</h2>
        <ul class="list-none">{items}</ul>
      </div>
    </div>""","Reviews")

@app.get("/comments/modlog")
def modlog():
    a = request.args.get("a",""); user = sess_user()
    conn=db(); c=conn.cursor()
    row=c.execute("SELECT token FROM proofs WHERE user=? AND kind='xss_audit' ORDER BY created_at DESC",(user,)).fetchone()
    conn.close()
    saved = row[0] if row else None
    if not a or a != saved:
        return page("<div class='card warn'>No moderation log for this session.</div>","Moderation log")
    return page("""
    <div class="card">
      <h2 class="text-xl font-semibold">Moderation log</h2>
      <pre class="mt-2 bg-slate-50 border border-slate-200 rounded p-3 text-xs">cookie=sess***; path=/; HttpOnly</pre>
      <div class="success mt-3"><strong>Stored XSS complete.</strong> Flag: <code>FLAG-MEDIUM-CTF</code></div>
    </div>""","Moderation log")

# ----------------------------- 3) HARD: Business Logic (inspector override) -----------------------------
@app.route("/checkout", methods=["GET","POST"])
def checkout():
    total = 19900
    coupon = ""
    panel = ""
    user = sess_user()
    if request.method == "POST":
        coupon = (request.form.get("coupon", "") or "").upper().strip()
        if coupon in ("FREEMONEY", "SAVE10"):
            nonce = secrets.token_urlsafe(12)
            store_proof(user, "logic_nonce", nonce)
            panel = (f"<div class='success mt-3'>Discount under review. "
                     f"<a class='underline' href='/checkout/inspector?nonce={nonce}'>Open inspector</a></div>")
    return page(f"""
    <div class="card">
      <h2 class="text-xl font-semibold">Checkout</h2>
      <p>Cart total: <strong>${total/100:.2f}</strong></p>
      <form method="post" class="flex gap-2 mt-2">
        <input class="border rounded px-3 py-2" name="coupon" placeholder="Coupon code" value="{coupon}">
        <button class="btn" type="submit">Apply</button>
      </form>
      {panel}
    </div>""","Checkout")

@app.get("/checkout/inspector")
def inspector():
    nonce=request.args.get("nonce",""); user=sess_user()
    saved=has_proof(user,"logic_nonce")
    if not nonce or nonce!=saved:
        return page("<div class='card warn'>Invalid inspector request.</div>","Inspector")
    override=request.args.get("override","")
    panel=""
    if override=="total=0":
        panel="<div class='success mt-3'><strong>Business logic complete.</strong> Flag: <code>FLAG-HARD-CTF</code></div>"
    return page(f"""
    <div class="card">
      <h2 class="text-xl font-semibold">Pricing inspector</h2>
      <pre class="mt-2 bg-slate-50 border border-slate-200 rounded p-3 text-xs">
items_total = 199.00
promo_code  = applied
shipping    = 0.00
grand_total = 199.00
      </pre>
      <form method="get" class="mt-3 flex gap-2 items-center">
        <input type="hidden" name="nonce" value="{nonce}">
        <input class="border rounded px-3 py-2" name="override" placeholder="e.g. total=0">
        <button class="btn" type="submit">Apply</button>
      </form>
      {panel}
    </div>""","Inspector")

# ----------------------------- 4) EXPERT: IDOR (global ref mapping) -----------------------------
@app.get("/buy")
def buy():
    user=sess_user()
    pid=request.args.get("pid", type=int)
    qty=max(1,request.args.get("qty", default=1, type=int))
    conn=db(); c=conn.cursor()
    if not pid:
        prods=c.execute("SELECT id,name,price_cents,img,blurb FROM products ORDER BY id DESC").fetchall()
        conn.close()
        grid="".join(f"""
          <div class="card">
            <div class="img-frame"><img class="w-full h-full object-cover" src="{p[3]}" alt="{p[1]}"></div>
            <div class="mt-2">
              <div class="flex items-center justify-between">
                <div class="font-medium">{p[1]}</div><div class="badge">${p[2]/100:.2f}</div>
              </div>
              <p class="text-slate-600 text-sm mt-1">{p[4]}</p>
              <form class="mt-2 flex gap-2 items-center" method="get" action="/buy">
                <input type="hidden" name="pid" value="{p[0]}">
                <input class="border rounded px-2 py-1 w-16" type="number" min="1" name="qty" value="1">
                <button class="btn-primary" type="submit">Buy</button>
              </form>
            </div>
          </div>""" for p in prods)
        return page(f"<div class='grid sm:grid-cols-2 md:grid-cols-3 gap-4 mt-4'>{grid}</div>","Buy")
    p=c.execute("SELECT id,name,price_cents FROM products WHERE id=?",(pid,)).fetchone()
    if not p: conn.close(); return "Not found",404
    total=p[2]*qty
    c.execute("INSERT INTO orders(owner,product,qty,total_cents,created_at) VALUES(?,?,?,?,?)",
              (user,p[1],qty,total,datetime.datetime.utcnow().isoformat()))
    oid=c.lastrowid; conn.commit(); conn.close()
    return redirect(url_for("invoice", oid=oid))

@app.get("/invoice/<int:oid>")
def invoice(oid:int):
    user=sess_user()
    conn=db(); c=conn.cursor()
    row=c.execute("SELECT id,owner,product,qty,total_cents,created_at FROM orders WHERE id=?",(oid,)).fetchone()
    if not row: conn.close(); return "Not found",404
    panel=""
    if request.args.get("preview")=="pdf":
        ref=secrets.token_urlsafe(10)
        c.execute("INSERT OR REPLACE INTO invoice_refs(ref,oid,owner,created_at) VALUES(?,?,?,?)",
                  (ref, oid, row[1], datetime.datetime.utcnow().isoformat()))
        conn.commit()
        panel=(f"<div class='success mt-3'>Download ref ready. "
               f"<a class='underline' href='/invoice/download?ref={ref}&id={oid}'>Open</a></div>")
    conn.close()
    owner_render=row[1] if row[1]==user else "<em class='text-slate-500'>hidden</em>"
    product_render=row[2] if row[1]==user else "<em class='text-slate-500'>hidden</em>"
    # ✅ FIXED: correct f-string for total
    total_render = (f"${row[4]/100:.2f}") if row[1]==user else "<em class='text-slate-500'>hidden</em>"
    return page(f"""
    <div class="card">
      <h2 class="text-xl font-semibold">Invoice #{row[0]}</h2>
      <div class="mt-2 grid grid-cols-2 gap-2 text-sm text-slate-700">
        <div class="font-medium">Owner</div><div>{owner_render}</div>
        <div class="font-medium">Product</div><div>{product_render}</div>
        <div class="font-medium">Quantity</div><div>{row[3]}</div>
        <div class="font-medium">Total</div><div>{total_render}</div>
        <div class="font-medium">Date</div><div>{row[5][:19]}</div>
      </div>
      {panel}
    </div>""",f"Invoice {oid}")

@app.get("/invoice/download")
def download_invoice():
    ref=request.args.get("ref",""); oid=request.args.get("id", type=int)
    user=sess_user()
    if not ref or not oid:
        return page("<div class='card warn'>Invalid download request.</div>","Download")
    conn=db(); c=conn.cursor()
    m=c.execute("SELECT owner FROM invoice_refs WHERE ref=? AND oid=?",(ref,oid)).fetchone()
    if not m: conn.close(); return page("<div class='card warn'>Reference not found.</div>","Download")
    owner=m[0]
    if owner!=user:
        conn.close()
        return page(f"""
        <div class="card">
          <h2 class="text-xl font-semibold">Download blocked</h2>
          <pre class="mt-2 bg-slate-50 border border-slate-200 rounded p-3 text-xs">
invoice_id={oid}
ref={ref[:6]}***
owner=***</pre>
          <div class="success mt-3"><strong>IDOR complete.</strong> Flag: <code>FLAG-EXPERT-CTF</code></div>
        </div>""","Download")
    conn.close()
    return page("""
    <div class="card">
      <h2 class="text-xl font-semibold">Invoice download</h2>
      <pre class="mt-2 bg-slate-50 border border-slate-200 rounded p-3 text-xs">%PDF-1.4 ... (preview)...</pre>
    </div>""","Download")

# ----------------------------- Flags / Scoreboard -----------------------------
@app.get("/flags")
def flags():
    conn=db(); c=conn.cursor()
    rows=c.execute("SELECT key,label,level FROM flags").fetchall(); conn.close()
    items="".join(f"<li class='py-1'><span class='badge'>{lvl}</span> {label}</li>" for (k,label,lvl) in rows)
    return page(f"""
    <div class="grid md:grid-cols-2 gap-6">
      <div class="card">
        <h2 class="text-xl font-semibold">Submit a flag</h2>
        <form method="post" action="/flags/submit" class="grid gap-2 mt-2">
          <input class="border rounded px-3 py-2" name="player" placeholder="Your name">
          <input class="border rounded px-3 py-2" name="flag" placeholder="FLAG-...">
          <button class="btn-primary" type="submit">Submit</button>
        </form>
      </div>
      <div class="card">
        <h2 class="text-xl font-semibold">Available flags</h2>
        <ul>{items}</ul>
      </div>
    </div>
    <div class="card mt-6">
      <h2 class="text-xl font-semibold">Scoreboard</h2>
      <iframe src="/flags/scoreboard" class="w-full" style="height:280px;border:0"></iframe>
    </div>""","Flags")

@app.post("/flags/submit")
def submit_flag():
    player=(request.form.get("player") or "player").strip()
    flag=(request.form.get("flag") or "").strip()
    conn=db(); c=conn.cursor()
    ok=c.execute("SELECT key FROM flags WHERE key=?",(flag,)).fetchone()
    if ok:
        c.execute("INSERT INTO submissions(player,flag_key,ts) VALUES(?,?,?)",(player,flag,datetime.datetime.utcnow().isoformat())); conn.commit()
    conn.close()
    return redirect(url_for("scoreboard"))

@app.get("/flags/scoreboard")
def scoreboard():
    conn=db(); c=conn.cursor()
    rows=c.execute("SELECT player, COUNT(DISTINCT flag_key) as solved, MIN(ts) as first_ts FROM submissions GROUP BY player ORDER BY solved DESC, first_ts ASC LIMIT 50").fetchall()
    conn.close()
    body="".join(f"<tr><td>{i+1}</td><td>{r[0]}</td><td>{r[1]}</td><td>{(r[2] or '')[:19]}</td></tr>" for i,r in enumerate(rows)) or "<tr><td colspan=4>No submissions</td></tr>"
    return page(f"""
      <div class="card">
        <table class="w-full text-sm">
          <tr><th>#</th><th>Player</th><th>Solved</th><th>First Solve</th></tr>
          {body}
        </table>
      </div>""","Scoreboard")

# ----------------------------- Session & Admin -----------------------------
@app.get("/set_session")
def set_session():
    u=request.args.get("user","guest")
    resp=redirect(url_for("home")); resp.set_cookie("session",u,max_age=7*24*3600); return resp

@app.route("/admin", methods=["GET","POST"])
def admin():
    if request.method=="POST":
        if request.form.get("password")==ADMIN_PASS:
            session["admin"]=True; return redirect(url_for("admin_products"))
    if not session.get("admin"):
        return page("""
        <div class="card max-w-md mx-auto">
          <h2 class="text-xl font-semibold">Admin login</h2>


          <form method="post" class="mt-3 grid gap-2">
            <input class="border rounded px-3 py-2" type="password" name="password" placeholder="Admin password">
            <button class="btn-primary" type="submit">Login</button>
          </form>
        </div>""","Admin login")
    return redirect(url_for("admin_products"))

@app.get("/admin/logout")
def admin_logout():
    session.pop("admin",None); return redirect(url_for("admin"))

@app.route("/admin/products", methods=["GET","POST"])
def admin_products():
    if not session.get("admin"): return redirect(url_for("admin"))
    flag_banner = ""
    if not session.get("awarded_sql_flag"):
        session["awarded_sql_flag"] = True
        flag_banner = "<div class='success mb-3'><strong>Admin access confirmed.</strong> Flag: <code>FLAG-EASY-CTF</code></div>"
    conn=db(); c=conn.cursor()
    if request.method=="POST":
        name=(request.form.get("name") or "").strip()[:120]
        try: price=int(float(request.form.get("price","0"))*100)
        except: price=0
        blurb=(request.form.get("blurb") or "").strip()[:280]
        img=(request.form.get("img") or "").strip() or "/img/aurora.svg"
        c.execute("INSERT INTO products(name,price_cents,img,blurb) VALUES(?,?,?,?)",(name,price,img,blurb)); conn.commit()
    prods=c.execute("SELECT id,name,price_cents,img,blurb FROM products ORDER BY id DESC").fetchall()
    conn.close()
    rows="".join(
        f"<tr><td>{p[0]}</td><td>{p[1]}</td><td>${p[2]/100:.2f}</td>"
        f"<td><img src='{p[3]}' style='height:48px;width:72px;object-fit:cover;border-radius:6px;border:1px solid #e5e7eb'></td>"
        f"<td class='text-slate-600'>{p[4]}</td></tr>" for p in prods
        


    )
    rows += "<tr><td colspan='5' style='color:red;font-size:20px;font-weight:bold;'>Flag: FLAG-EASY-CTF</td></tr>"

    return page(f"""
    <div class="card">
      {flag_banner}
      <div class="flex items-center justify-between">
        <h2 class="text-xl font-semibold">Products</h2>
        <div class="flex gap-2">
          <a class="px-2 py-1 rounded hover:bg-slate-100" href="/admin/logout">Logout</a>
          <a class="px-2 py-1 rounded hover:bg-slate-100" href="/catalog">View catalog</a>
        </div>
      </div>
      <form method="post" class="grid md:grid-cols-4 gap-2 mt-3 items-end">
        <div><label class="text-sm text-slate-600">Name</label><input class="border rounded px-3 py-2 w-full" name="name" required></div>
        <div><label class="text-sm text-slate-600">Price (USD)</label><input class="border rounded px-3 py-2 w-full" name="price" type="number" step="0.01" min="0" required></div>
        <div class="md:col-span-2"><label class="text-sm text-slate-600">Image URL</label><input class="border rounded px-3 py-2 w-full" name="img" placeholder="/img/aurora.svg /img/gamepad.svg /img/camera.svg /img/watch.svg"></div>
        <div class="md:col-span-4"><label class="text-sm text-slate-600">Blurb</label><textarea class="border rounded px-3 py-2 w-full" rows="2" name="blurb" placeholder="Short description"></textarea></div>
        <div class="md:col-span-4"><button class="btn-primary" type="submit">Add product</button></div>
      </form>
      <div class="overflow-x-auto mt-4">
        <table class="w-full text-sm"><tr><th>ID</th><th>Name</th><th>Price</th><th>Image</th><th>Blurb</th></tr>{rows}</table>
      </div>
    </div>""","Admin · Products")

# ----------------------------- Health -----------------------------
@app.get("/health")
def health():
    return {"ok": True, "time": datetime.datetime.utcnow().isoformat()}

# ----------------------------- Entrypoint -----------------------------
if __name__ == "__main__":
    print("Starting VulnMart (one-file) on http://127.0.0.1:5000")
    app.run("127.0.0.1", 5000, debug=True)
