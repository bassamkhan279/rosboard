#!/usr/bin/env python3
import threading
import subprocess
import pathlib
import json
from aiohttp import web, ClientSession
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session

# ---------- Paths ----------
BASE_DIR = pathlib.Path(__file__).parent
WEB_DIR = BASE_DIR / "web"

# ---------- Supabase (PostgREST & Auth) HTTP config ----------
SUPABASE_URL = "https://pxlbmyygaiqevnbcrnmj.supabase.co"
SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1OTk5OTIwNCwiZXhwIjoyMDc1NTc1MjA0fQ.ufkzZDGdo9wUzdc2SgbYcMKAVuUxKpIkzzRjJqfLRuA"
ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTk5OTkyMDQsImV4cCI6MjA3NTU3NTIwNH0.ZLYal4RUIM8BISLiGQorh-hVN_VDSPqjJjB2WnN4V04"

# Base URLs
POSTGREST_BASE = f"{SUPABASE_URL}/rest/v1"
AUTH_BASE = f"{SUPABASE_URL}/auth/v1"

# ---------- HTTP Helper Functions ----------
def _supabase_headers():
    return {
        "apikey": SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

def _auth_headers(jwt=None):
    headers = {
        "apikey": ANON_KEY,
        "Content-Type": "application/json"
    }
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    return headers

async def sb_get(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.get(url, headers=_supabase_headers(), params=params) as resp:
        return resp.status, await resp.json()

async def sb_post(session: ClientSession, path: str, payload: dict):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.post(url, headers=_supabase_headers(), json=payload) as resp:
        return resp.status, await resp.json()

async def sb_patch(session: ClientSession, path: str, payload: dict, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.patch(url, headers=_supabase_headers(), params=params, json=payload) as resp:
        return resp.status, await resp.json()

async def sb_delete(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.delete(url, headers=_supabase_headers(), params=params) as resp:
        return resp.status, await resp.json()

async def sb_auth_post(session: ClientSession, path: str, payload: dict):
    url = f"{AUTH_BASE}/{path}"
    async with session.post(url, headers=_auth_headers(), json=payload) as resp:
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": await resp.text()}
        return resp.status, data

async def sb_auth_put(session: ClientSession, path: str, payload: dict, jwt: str):
    url = f"{AUTH_BASE}/{path}"
    async with session.put(url, headers=_auth_headers(jwt=jwt), json=payload) as resp:
        return resp.status, await resp.json()

# ---------- App Startup / Cleanup ----------
async def on_startup(app):
    print("[Supabase] Creating HTTP client session")
    app["http_client"] = ClientSession()

async def on_cleanup(app):
    print("[Supabase] Closing HTTP client session")
    await app["http_client"].close()

# ---------- SECURE LOGIN ----------
async def login_page(request):
    login_path = WEB_DIR / "login.html"
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        password = data.get("password")

        payload = {"email": email, "password": password}
        status, result = await sb_auth_post(
            request.app["http_client"], "token?grant_type=password", payload
        )

        if status == 200 and "access_token" in result:
            jwt_token = result["access_token"]
            session = await get_session(request)
            session["user"] = {"email": email, "jwt": jwt_token}
            print(f"[Login] ✅ Authenticated via Supabase Auth: {email}")
            raise web.HTTPFound("/rosboard")
        else:
            print(f"[Login] ❌ Auth failed for {email}: {result}")
            return web.Response(text="Invalid email or password", status=401)

    return web.FileResponse(login_path)

# ---------- SECURE REGISTER ----------
async def register_page(request):
    register_path = WEB_DIR / "register.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        password = data.get("password")
        role = data.get("role", "user")

        # ✅ Register securely via Supabase Auth (hashed password)
        payload = {"email": email, "password": password}
        status, result = await sb_auth_post(request.app["http_client"], "signup", payload)

        if status in [200, 201]:
            # Add profile entry for user roles (optional)
            profile_payload = {"email": email, "role": role}
            await sb_post(request.app["http_client"], "profiles", profile_payload)
            print(f"[Register] ✅ User {email} registered via Supabase Auth (role: {role})")
            raise web.HTTPFound("/login")
        else:
            print(f"[Register] ❌ Failed to register {email}: {result}")
            return web.Response(text="Failed to register user", status=status)

    return web.FileResponse(register_path)

# ---------- LOGOUT ----------
async def logout(request):
    session = await get_session(request)
    session.invalidate()
    print("[Logout] ✅ User logged out")
    raise web.HTTPFound("/login")

# ---------- PASSWORD RESET ----------
async def forgot_password_page(request):
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        payload = {"email": email}
        # ✅ Fixed path (no leading slash)
        status, result = await sb_auth_post(request.app["http_client"], "recover", payload)

        if status == 200:
            msg = "If an account exists, a password reset link has been sent."
            print(f"[Password Reset] ✅ Recovery email initiated for {email}")
            return web.Response(text=msg, status=200)
        else:
            msg = f"Error requesting password reset: {result.get('msg', 'Unknown error')}"
            print(f"[Password Reset] ❌ Failed for {email}: {result}")
            return web.Response(text=msg, status=status)

    return web.FileResponse(WEB_DIR / "forgot_password.html")

async def reset_password_page(request):
    if request.method == "POST":
        data = await request.post()
        access_token = data.get("access_token")
        new_password = data.get("password")

        if not access_token or not new_password:
            return web.Response(text="Missing token or password.", status=400)

        payload = {"password": new_password}
        status, result = await sb_auth_put(request.app["http_client"], "user", payload, jwt=access_token)

        if status == 200:
            print(f"[Password Reset] ✅ Password updated successfully.")
            return web.Response(text="Password updated successfully!", status=200)
        else:
            error_msg = result.get('msg', 'Failed to update password.')
            print(f"[Password Reset] ❌ Failed to update password: {result}")
            return web.Response(text=error_msg, status=status)

    return web.FileResponse(WEB_DIR / "reset_password.html")

# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    path = request.path
    public_paths = ["/login", "/register", "/forgot-password", "/reset-password", "/logout"]
    if any(path.startswith(p) for p in public_paths) or path.startswith("/static"):
        return await handler(request)

    session = await get_session(request)
    if path == "/":
        raise web.HTTPFound("/login" if "user" not in session else "/rosboard")

    if "user" in session and path.startswith("/rosboard"):
        return await handler(request) 

    if "user" not in session:
        raise web.HTTPFound("/login")

    return await handler(request)

# ---------- ROSBoard Proxy (Now on Port 8899) ----------
async def rosboard_proxy(request):
    client_session = request.app["http_client"]
    target_url = f"http://localhost:8899{request.path_qs}"

    try:
        async with client_session.request(
            request.method,
            target_url,
            headers=request.headers,
            data=await request.read()
        ) as resp:
            response = web.Response(
                status=resp.status,
                headers=resp.headers,
                body=await resp.read()
            )
            response.headers.pop('Transfer-Encoding', None)
            return response
    except Exception as e:
        print(f"[Rosboard Proxy] ❌ Error connecting to backend: {e}")
        return web.Response(text="Rosboard backend is not reachable.", status=502)

# ---------- Admin Page & API ----------
async def admin_page(request):
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        raise web.HTTPFound("/rosboard")
    return web.FileResponse(WEB_DIR / "admin.html")

async def admin_only(request):
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        return web.Response(text="Forbidden", status=403)
    return None

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
    subprocess.Popen(["python3", "-m", "rosboard", "--port", "8899"])

# ---------- App Setup ----------
def main():
    print("[ROSBoard] 🔧 Starting login + admin server...")
    threading.Thread(target=run_rosboard_backend, daemon=True).start()

    app = web.Application(middlewares=[
        aiohttp_session.session_middleware(SimpleCookieStorage()),
        require_login_middleware
    ])

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Routes
    app.router.add_get("/", login_page)
    app.router.add_route("*", "/login", login_page)
    app.router.add_get("/logout", logout)
    app.router.add_route("*", "/register", register_page)
    app.router.add_route("*", "/forgot-password", forgot_password_page)
    app.router.add_route("*", "/reset-password", reset_password_page)
    app.router.add_get("/admin", admin_page)
    app.router.add_route("*", "/rosboard", rosboard_proxy)
    app.router.add_route("*", "/rosboard/{path_info:.*}", rosboard_proxy)
    app.router.add_get("/api/users", get_users)
    app.router.add_post("/api/users", create_user)
    app.router.add_put("/api/users/{id}", update_user)
    app.router.add_delete("/api/users/{id}", delete_user)
    app.router.add_static("/static/", path=str(WEB_DIR / "static"), name="static")

    print("[ROSBoard] ✅ Server running at: http://localhost:8888")
    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()
