import threading
import subprocess
import pathlib
from aiohttp import web
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session
import asyncpg
import json

# ---------- Paths ----------
webdir = pathlib.Path(__file__).parent / "web"
html_dir = pathlib.Path(__file__).parent / "html"

# ---------- Database Setup ----------
async def init_db(app):
    print("[Database] Connecting to Supabase...")
    app['db'] = await asyncpg.create_pool(
        user='postgres',
        password='MZDtjmdksMyktjXo',  
        database='postgres',
        host='db.pxlbmyygaiqevnbcrnmj.supabase.co', 
        port=5432,
        ssl='require'
    )
    print("[Database] Connected!")

async def close_db(app):
    await app['db'].close()
    print("[Database] Connection closed.")

# ---------- Login Page ----------
async def login_page(request):
    login_path = webdir / "login.html"

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
            raise web.HTTPFound("/rosboard")  # ✅ Everyone goes to /rosboard
        else:
            return web.Response(text="Invalid credentials", status=401)

    return web.FileResponse(login_path)

# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    # ✅ Allow login and static files without session
    if request.path.startswith("/login") or request.path.startswith("/static"):
        return await handler(request)

    # ✅ Redirect root "/" to /login if not logged in
    if request.path == "/":
        session = await get_session(request)
        if "user" not in session:
            raise web.HTTPFound("/login")
        else:
            raise web.HTTPFound("/rosboard")

    # ✅ Require login for all other routes
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")

    return await handler(request)

# ---------- ROSBoard Page ----------
async def rosboard_page(request):
    index_path = html_dir / "index.html"
    return web.FileResponse(index_path)

# ---------- Admin Page ----------
async def admin_page(request):
    session = await get_session(request)
    user = session.get("user")

    if not user or user.get("role") != "admin":
        raise web.HTTPFound("/rosboard")

    admin_html = webdir / "admin.html"
    return web.FileResponse(admin_html)

# ---------- API: Manage Users (Admin only) ----------
async def admin_only(request):
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        return web.Response(text="Forbidden", status=403)
    return None

async def get_users(request):
    await admin_only(request)
    async with request.app['db'].acquire() as conn:
        users = await conn.fetch("SELECT id, email, role, created_at FROM profiles ORDER BY created_at DESC")
    return web.json_response([dict(u) for u in users])

async def create_user(request):
    await admin_only(request)
    data = await request.json()
    async with request.app['db'].acquire() as conn:
        await conn.execute(
            "INSERT INTO profiles (email, password, role, created_at) VALUES ($1, $2, $3, NOW())",
            data["email"], data["password"], data["role"]
        )
    return web.json_response({"status": "ok"})

async def update_user(request):
    await admin_only(request)
    user_id = request.match_info["id"]
    data = await request.json()
    async with request.app['db'].acquire() as conn:
        await conn.execute(
            "UPDATE profiles SET email=$1, password=$2, role=$3 WHERE id=$4",
            data["email"], data["password"], data["role"], user_id
        )
    return web.json_response({"status": "updated"})

async def delete_user(request):
    await admin_only(request)
    user_id = request.match_info["id"]
    async with request.app['db'].acquire() as conn:
        await conn.execute("DELETE FROM profiles WHERE id=$1", user_id)
    return web.json_response({"status": "deleted"})

# ---------- ROSBoard Backend ----------
def run_rosboard_backend():
    subprocess.Popen(["python3", "-m", "rosboard", "--port", "8889"])


# ---------- Main ----------
def main():
    print("[ROSBoard] Login + Database + Admin server starting...")

    threading.Thread(target=run_rosboard_backend, daemon=True).start()

    app = web.Application(middlewares=[
        aiohttp_session.session_middleware(SimpleCookieStorage()),
        require_login_middleware
    ])

    app.on_startup.append(init_db)
    app.on_cleanup.append(close_db)

    # Routes
    app.router.add_route("GET", "/", login_page)  # ✅ Root redirects to login
    app.router.add_route("GET", "/login", login_page)
    app.router.add_route("POST", "/login", login_page)
    app.router.add_route("GET", "/rosboard", rosboard_page)
    app.router.add_route("GET", "/admin", admin_page)

    # Admin APIs
    app.router.add_get("/api/users", get_users)
    app.router.add_post("/api/users", create_user)
    app.router.add_put("/api/users/{id}", update_user)
    app.router.add_delete("/api/users/{id}", delete_user)

    app.router.add_static("/static/", path=str(webdir / "static"), name="static")

    print("[ROSBoard] Server running on http://localhost:8888")
    print("After login → http://localhost:8888/rosboard")
    print("Admins can visit → http://localhost:8888/admin")

    web.run_app(app, host="0.0.0.0", port=8888)


if __name__ == "__main__":
    main()
