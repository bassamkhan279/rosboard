#!/usr/bin/env python3
#!/usr/bin/env python3
import threading
import subprocess
import pathlib
from aiohttp import web
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session
from supabase import create_client, Client

# ---------- Paths ----------
BASE_DIR = pathlib.Path(__file__).parent
WEB_DIR = BASE_DIR / "web"
HTML_DIR = BASE_DIR / "html"

# ---------- Supabase Setup ----------
SUPABASE_URL = "https://pxlbmyygaiqevnbcrnmj.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1OTk5OTIwNCwiZXhwIjoyMDc1NTc1MjA0fQ.ufkzZDGdo9wUzdc2SgbYcMKAVuUxKpIkzzRjJqfLRuA"  # use service_role key from Supabase dashboard
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------- Login Page ----------
async def login_page(request):
    login_path = WEB_DIR / "login.html"

    if request.method == "POST":
        data = await request.post()
        user = data.get("username")
        pwd = data.get("password")

        response = supabase.table("profiles").select("*").eq("email", user).eq("password", pwd).execute()
        if response.data and len(response.data) > 0:
            session = await get_session(request)
            session["user"] = response.data[0]
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
    register_path = WEB_DIR / "register.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        password = data.get("password")

        # Check if email already exists
        existing = supabase.table("profiles").select("*").eq("email", email).execute()
        if existing.data and len(existing.data) > 0:
            return web.Response(text="Email already exists", status=400)

        supabase.table("profiles").insert({
            "email": email,
            "password": password,
            "role": "user"
        }).execute()

        print(f"[Register] ✅ New user created: {email}")
        raise web.HTTPFound("/login")

    return web.FileResponse(register_path)

# ---------- Forgot Password Page ----------
async def forgot_password_page(request):
    forgot_path = WEB_DIR / "forgot_password.html"

    if request.method == "POST":
        data = await request.post()
        email = data.get("email")

        user = supabase.table("profiles").select("*").eq("email", email).execute()
        if not user.data:
            return web.Response(text="Email not found", status=404)

        # Simulate password reset
        print(f"[ForgotPassword] Link sent to {email}")
        return web.Response(text="Password reset link sent (simulated).", status=200)

    return web.FileResponse(forgot_path)

# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    path = request.path
    if path.startswith("/login") or path.startswith("/static") or path == "/logout" or path.startswith("/register") or path.startswith("/forgot"):
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
    users = supabase.table("profiles").select("id,email,role,created_at").order("created_at", desc=True).execute()
    return web.json_response(users.data)

async def create_user(request):
    check = await admin_only(request)
    if check: return check
    data = await request.json()
    supabase.table("profiles").insert({
        "email": data["email"],
        "password": data["password"],
        "role": data["role"]
    }).execute()
    return web.json_response({"status": "ok"})

async def update_user(request):
    check = await admin_only(request)
    if check: return check
    user_id = request.match_info["id"]
    data = await request.json()
    supabase.table("profiles").update({
        "email": data["email"],
        "password": data["password"],
        "role": data["role"]
    }).eq("id", user_id).execute()
    return web.json_response({"status": "updated"})

async def delete_user(request):
    check = await admin_only(request)
    if check: return check
    user_id = request.match_info["id"]
    supabase.table("profiles").delete().eq("id", user_id).execute()
    return web.json_response({"status": "deleted"})

# ---------- Run ROSBoard Backend ----------
def run_rosboard_backend():
    subprocess.Popen(["python3", "-m", "rosboard", "--port", "8889"])

# ---------- App Setup ----------
def main():
    print("[ROSBoard] 🔧 Starting login + admin server...")
    threading.Thread(target=run_rosboard_backend, daemon=True).start()

    app = web.Application(middlewares=[
        aiohttp_session.session_middleware(SimpleCookieStorage()),
        require_login_middleware
    ])

    # --- ROUTES ---
    app.router.add_get("/", login_page)
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_page)
    app.router.add_get("/logout", logout)
    app.router.add_get("/rosboard", rosboard_page)
    app.router.add_get("/admin", admin_page)
    app.router.add_get("/register", register_page)
    app.router.add_post("/register", register_page)
    app.router.add_get("/forgot", forgot_password_page)
    app.router.add_post("/forgot", forgot_password_page)

    # --- Admin APIs ---
    app.router.add_get("/api/users", get_users)
    app.router.add_post("/api/users", create_user)
    app.router.add_put("/api/users/{id}", update_user)
    app.router.add_delete("/api/users/{id}", delete_user)

    # --- Static assets ---
    app.router.add_static("/static/", path=str(WEB_DIR / "static"), name="static")

    print("[ROSBoard] ✅ Server running at: http://localhost:8888")
    print("   → Login Page: http://localhost:8888/login")
    print("   → Register Page: http://localhost:8888/register")
    print("   → Forgot Password: http://localhost:8888/forgot")
    print("   → Main ROSBoard: http://localhost:8888/rosboard")
    print("   → Admin Panel: http://localhost:8888/admin")

    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()
