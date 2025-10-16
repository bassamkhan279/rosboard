#!/usr/bin/env python3
import threading
import subprocess
import pathlib
import json
import urllib.parse
from aiohttp import web, ClientSession
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session

# ---------- Paths ----------
BASE_DIR = pathlib.Path(__file__).parent
WEB_DIR = BASE_DIR / "web"
HTML_DIR = BASE_DIR / "html"

# ---------- Supabase (PostgREST) HTTP config ----------
# Replace SERVICE_ROLE_KEY with your real service_role key (keep it secret)
SUPABASE_URL = "https://pxlbmyygaiqevnbcrnmj.supabase.co"  # your project host
SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1OTk5OTIwNCwiZXhwIjoyMDc1NTc1MjA0fQ.ufkzZDGdo9wUzdc2SgbYcMKAVuUxKpIkzzRjJqfLRuA"

# REST base for the public PostgREST endpoints:
POSTGREST_BASE = f"{SUPABASE_URL}/rest/v1"

# Standard headers for server-side (service role) requests:
def _supabase_headers():
    return {
        "apikey": SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        # Prefer header to return the created/updated rows when requested
        "Prefer": "return=representation",
    }

# ---------- Helper HTTP functions (async) ----------
async def sb_get(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.get(url, headers=_supabase_headers(), params=params) as resp:
        text = await resp.text()
        try:
            data = await resp.json()
        except Exception:
            data = {"error": text}
        return resp.status, data

async def sb_post(session: ClientSession, path: str, payload: dict):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.post(url, headers=_supabase_headers(), data=json.dumps(payload)) as resp:
        text = await resp.text()
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": text}
        return resp.status, data

async def sb_patch(session: ClientSession, path: str, payload: dict, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    # PATCH using PostgREST: send PATCH to resource with query in URL
    async with session.patch(url, headers=_supabase_headers(), params=params, data=json.dumps(payload)) as resp:
        text = await resp.text()
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": text}
        return resp.status, data

async def sb_delete(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.delete(url, headers=_supabase_headers(), params=params) as resp:
        text = await resp.text()
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": text}
        return resp.status, data

# ---------- App startup / cleanup to create HTTP session ----------
async def on_startup(app):
    print("[Supabase] Creating HTTP client session")
    app["http_client"] = ClientSession()

async def on_cleanup(app):
    print("[Supabase] Closing HTTP client session")
    await app["http_client"].close()

# ---------- Login Page ----------
async def login_page(request):
    login_path = WEB_DIR / "login.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("username")
        pwd = data.get("password")

        # Use GET query to filter rows: ?email=eq.<email>&password=eq.<pwd>
        # put params in dict so aiohttp encodes them.
        params = {
            "email": f"eq.{email}",
            "password": f"eq.{pwd}",
            "select": "*"
        }
        status, data = await sb_get(request.app["http_client"], "profiles", params=params)
        if status == 200 and isinstance(data, list) and len(data) > 0:
            session = await get_session(request)
            session["user"] = data[0]  # store user record
            print(f"[Login] ✅ User '{email}' logged in.")
            raise web.HTTPFound("/rosboard")
        else:
            print("[Login] ❌ Invalid credentials or user not found.")
            return web.Response(text="Invalid credentials", status=401)

    return web.FileResponse(login_path)

# ---------- Logout ----------
async def logout(request):
    session = await get_session(request)
    session.invalidate()
    raise web.HTTPFound("/login")

# ---------- Register Page ----------
async def register_page(request):
    register_path = WEB_DIR / "register.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        password = data.get("password")

        # check existence
        params = {"email": f"eq.{email}", "select": "id"}
        status, existing = await sb_get(request.app["http_client"], "profiles", params=params)
        if status == 200 and isinstance(existing, list) and len(existing) > 0:
            return web.Response(text="Email already exists", status=400)

        payload = {"email": email, "password": password, "role": "user"}
        status, created = await sb_post(request.app["http_client"], "profiles", payload)
        if status in (201, 200):
            print(f"[Register] ✅ New user created: {email}")
            raise web.HTTPFound("/login")
        else:
            print("[Register] ❌ Failed to create user:", created)
            return web.Response(text="Failed to create user", status=500)

    return web.FileResponse(register_path)

# ---------- Forgot Password Page ----------
async def forgot_password_page(request):
    forgot_path = WEB_DIR / "forgot_password.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("email")

        params = {"email": f"eq.{email}", "select": "id,email"}
        status, found = await sb_get(request.app["http_client"], "profiles", params=params)
        if status == 200 and isinstance(found, list) and len(found) > 0:
            # simulate reset (you can implement email sending via Supabase Auth SMTP later)
            print(f"[ForgotPassword] Simulated reset link for {email}")
            return web.Response(text="Password reset link sent (simulated).", status=200)
        else:
            return web.Response(text="Email not found", status=404)

    return web.FileResponse(forgot_path)

# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    path = request.path
    # allow public paths
    if path.startswith("/login") or path.startswith("/register") or path.startswith("/forgot") or path.startswith("/static") or path == "/logout":
        return await handler(request)

    # Root redirect behavior
    if path == "/":
        session = await get_session(request)
        if "user" not in session:
            raise web.HTTPFound("/login")
        else:
            raise web.HTTPFound("/rosboard")

    # require session for others
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")

    return await handler(request)

# ---------- ROSBoard Page ----------
async def rosboard_page(request):
    index_path = HTML_DIR / "index.html"
    return web.FileResponse(index_path)

# ---------- Admin Page ----------
async def admin_page(request):
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        raise web.HTTPFound("/rosboard")
    admin_html = WEB_DIR / "admin.html"
    return web.FileResponse(admin_html)

# ---------- Admin helper ----------
async def admin_only(request):
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        return web.Response(text="Forbidden", status=403)
    return None

# ---------- Admin APIs (CRUD) ----------
async def get_users(request):
    check = await admin_only(request)
    if check: return check
    params = {"select": "id,email,role,created_at", "order": "created_at.desc"}
    status, data = await sb_get(request.app["http_client"], "profiles", params=params)
    return web.json_response(data)

async def create_user(request):
    check = await admin_only(request)
    if check: return check
    data = await request.json()
    payload = {"email": data["email"], "password": data["password"], "role": data["role"]}
    status, res = await sb_post(request.app["http_client"], "profiles", payload)
    return web.json_response({"status": "ok", "result": res})

async def update_user(request):
    check = await admin_only(request)
    if check: return check
    user_id = request.match_info["id"]
    data = await request.json()
    # PostgREST update: PATCH /profiles?id=eq.<user_id>
    params = {"id": f"eq.{user_id}"}
    payload = {"email": data["email"], "password": data["password"], "role": data["role"]}
    status, res = await sb_patch(request.app["http_client"], "profiles", payload, params=params)
    return web.json_response({"status": "updated", "result": res})

async def delete_user(request):
    check = await admin_only(request)
    if check: return check
    user_id = request.match_info["id"]
    params = {"id": f"eq.{user_id}"}
    status, res = await sb_delete(request.app["http_client"], "profiles", params=params)
    return web.json_response({"status": "deleted", "result": res})

# ---------- Run ROSBoard Backend ----------
def run_rosboard_backend():
    # Keep original behavior (run rosboard node)
    subprocess.Popen(["python3", "-m", "rosboard", "--port", "8889"])

# ---------- App setup ----------
def main():
    print("[ROSBoard] 🔧 Starting login + admin server...")

    # start rosboard backend in background
    threading.Thread(target=run_rosboard_backend, daemon=True).start()

    # aiohttp app + session middleware
    app = web.Application(middlewares=[
        aiohttp_session.session_middleware(SimpleCookieStorage()),
        require_login_middleware
    ])

    # http client lifecycle
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # routes
    app.router.add_get("/", login_page)
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_page)
    app.router.add_get("/logout", logout)
    app.router.add_get("/register", register_page)
    app.router.add_post("/register", register_page)
    app.router.add_get("/forgot-password", forgot_password_page)
    app.router.add_post("/forgot-password", forgot_password_page)
    app.router.add_get("/rosboard", rosboard_page)
    app.router.add_get("/admin", admin_page)

    # admin APIs
    app.router.add_get("/api/users", get_users)
    app.router.add_post("/api/users", create_user)
    app.router.add_put("/api/users/{id}", update_user)
    app.router.add_delete("/api/users/{id}", delete_user)

    # static files
    app.router.add_static("/static/", path=str(WEB_DIR / "static"), name="static")

    print("[ROSBoard] ✅ Server running at: http://localhost:8888")
    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()
