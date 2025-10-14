#!/usr/bin/env python3
import threading
import subprocess
import pathlib
import json
import asyncpg
from aiohttp import web
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session

# ---------- Paths ----------
BASE_DIR = pathlib.Path(__file__).parent
WEB_DIR = BASE_DIR / "web"
HTML_DIR = BASE_DIR / "html"

# ---------- Database Setup ----------
async def init_db(app):
    print("[Database] Connecting to Supabase PostgreSQL...")
    app['db'] = await asyncpg.create_pool(
        user='postgres',
        password='MZDtjmdksMyktjXo',
        database='postgres',
        host='db.pxlbmyygaiqevnbcrnmj.supabase.co',
        port=5432,
        ssl='require'
    )
    print("[Database] ✅ Connected!")

async def close_db(app):
    await app['db'].close()
    print("[Database] ❌ Connection closed.")

# ---------- Login Page ----------
async def login_page(request):
    login_path = WEB_DIR / "login.html"

    if request.method == "POST":
        data = await request.post()
        user = data.get("username")
        pwd = data.get("password")

        async with request.app['db'].acquire() as conn:
            record = await conn.fetchrow(
                "SELECT * FROM profiles WHERE email=$1 AND password=$2",
                user, pwd
            )

        if record:
            session = await get_session(request)
            session["user"] = dict(record)
            print(f"[Login] ✅ User '{user}' logged in.")
            raise web.HTTPFound("/rosboard")
        else:
            print("[Login] ❌ Invalid credentials.")
            return web.Response(text="Invalid credentials", status=401)

    return web.FileResponse(login_path)

# ---------- Logout ----------
async def logout(request):
    session = await get_session(request)
    session.invalidate()
    raise web.HTTPFound("/login")

# ---------- Register Page ----------
async def register_page(request):
    register_path = webdir / "register.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        password = data.get("password")

        async with request.app['db'].acquire() as conn:
            existing = await conn.fetchrow("SELECT * FROM profiles WHERE email=$1", email)
            if existing:
                return web.Response(text="Email already exists", status=400)

            await conn.execute(
                "INSERT INTO profiles (email, password, role, created_at) VALUES ($1, $2, $3, NOW())",
                email, password, "user"
            )

        raise web.HTTPFound("/login")

    return web.FileResponse(register_path)


# ---------- Forgot Password Page ----------
async def forgot_password_page(request):
    forgot_path = webdir / "forgot_password.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("email")

        async with request.app['db'].acquire() as conn:
            user = await conn.fetchrow("SELECT * FROM profiles WHERE email=$1", email)
            if not user:
                return web.Response(text="Email not found", status=404)

        # ✅ For now, we just show success — later, integrate Supabase email service
        return web.Response(text="Password reset link sent (simulated).", status=200)

    return web.FileResponse(forgot_path)


# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    path = request.path
    if path.startswith("/login") or path.startswith("/static") or path == "/logout":
        return await handler(request)

    # Redirect root "/" to login or /rosboard
    if path == "/":
        session = await get_session(request)
        if "user" not in session:
            raise web.HTTPFound("/login")
        else:
            raise web.HTTPFound("/rosboard")

    # Require login for everything else
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
        print("[Admin] ❌ Non-admin tried to access admin page.")
        raise web.HTTPFound("/rosboard")

    admin_html = WEB_DIR / "admin.html"
    return web.FileResponse(admin_html)

# ---------- Helper: Admin Only ----------
async def admin_only(request):
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        return web.Response(text="Forbidden", status=403)
    return None

# ---------- Admin APIs ----------
async def get_users(request):
    check = await admin_only(request)
    if check: return check
    async with request.app['db'].acquire() as conn:
        users = await conn.fetch("SELECT id, email, role, created_at FROM profiles ORDER BY created_at DESC")
    return web.json_response([dict(u) for u in users])

async def create_user(request):
    check = await admin_only(request)
    if check: return check
    data = await request.json()
    async with request.app['db'].acquire() as conn:
        await conn.execute(
            "INSERT INTO profiles (email, password, role, created_at) VALUES ($1, $2, $3, NOW())",
            data["email"], data["password"], data["role"]
        )
    return web.json_response({"status": "ok"})

async def update_user(request):
    check = await admin_only(request)
    if check: return check
    user_id = request.match_info["id"]
    data = await request.json()
    async with request.app['db'].acquire() as conn:
        await conn.execute(
            "UPDATE profiles SET email=$1, password=$2, role=$3 WHERE id=$4",
            data["email"], data["password"], data["role"], user_id
        )
    return web.json_response({"status": "updated"})

async def delete_user(request):
    check = await admin_only(request)
    if check: return check
    user_id = request.match_info["id"]
    async with request.app['db'].acquire() as conn:
        await conn.execute("DELETE FROM profiles WHERE id=$1", user_id)
    return web.json_response({"status": "deleted"})

# ---------- Run ROSBoard Backend ----------
def run_rosboard_backend():
    subprocess.Popen(["python3", "-m", "rosboard", "--port", "8889"])

# ---------- App Setup ----------
def main():
    print("[ROSBoard] 🔧 Starting login + admin server...")

    # Start rosboard in background
    threading.Thread(target=run_rosboard_backend, daemon=True).start()

    # Setup aiohttp app
    app = web.Application(middlewares=[
        aiohttp_session.session_middleware(SimpleCookieStorage()),
        require_login_middleware
    ])

    app.on_startup.append(init_db)
    app.on_cleanup.append(close_db)

    # --- ROUTES ---
    app.router.add_get("/", login_page)
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_page)
    app.router.add_get("/logout", logout)
    app.router.add_get("/rosboard", rosboard_page)
    app.router.add_get("/admin", admin_page)

    # --- Admin APIs ---
    app.router.add_get("/api/users", get_users)
    app.router.add_post("/api/users", create_user)
    app.router.add_put("/api/users/{id}", update_user)
    app.router.add_delete("/api/users/{id}", delete_user)

    # --- Static assets ---
    app.router.add_static("/static/", path=str(WEB_DIR / "static"), name="static")

    print("[ROSBoard] ✅ Server running at: http://localhost:8888")
    print("   → Login Page: http://localhost:8888/login")
    print("   → Main ROSBoard: http://localhost:8888/rosboard")
    print("   → Admin Panel: http://localhost:8888/admin")

    web.run_app(app, host="0.0.0.0", port=8888)


if __name__ == "__main__":
    main()
