#!/usr/bin/env python3
import threading
import subprocess
import pathlib
import json
import sys
import socket
from aiohttp import web, ClientSession
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session

# ---------- Prevent Recursive Self-Spawning ----------
if sys.argv[0].endswith("__main__.py"):
    SPAWN_BACKEND = False
else:
    SPAWN_BACKEND = True

# ---------- Paths ----------
BASE_DIR = pathlib.Path(__file__).parent
WEB_DIR = BASE_DIR / "web"

# ---------- Supabase Config ----------
SUPABASE_URL = "https://pxlbmyygaiqevnbcrnmj.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTk5OTkyMDQsImV4cCI6MjA3NTU3NTIwNH0.ZLYal4RUIM8BISLiGQorh-hVN_VDSPqjJjB2WnN4V04"
SUPABASE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1OTk5OTIwNCwiZXhwIjoyMDc1NTc1MjA0fQ.ufkzZDGdo9wUzdc2SgbYcMKAVuUxKpIkzzRjJqfLRuA"

POSTGREST_BASE = f"{SUPABASE_URL}/rest/v1"
AUTH_BASE = f"{SUPABASE_URL}/auth/v1" # 🟢 FIX: Added Auth base URL

# ---------- Helper HTTP functions ----------
def _supabase_headers():
    return {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

# 🟢 FIX: Added Auth header helper
def _auth_headers(jwt=None):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json"
    }
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    return headers

# 🟢 FIX: Added Auth POST helper
async def sb_auth_post(session: ClientSession, path: str, payload: dict):
    url = f"{AUTH_BASE}/{path}"
    async with session.post(url, headers=_auth_headers(), json=payload) as resp:
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": await resp.text()}
        return resp.status, data

async def sb_get(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.get(url, headers=_supabase_headers(), params=params) as resp:
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"error": await resp.text()}

async def sb_post(session: ClientSession, path: str, payload: dict):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.post(url, headers=_supabase_headers(), data=json.dumps(payload)) as resp:
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"raw": await resp.text()}

# ---------- App startup / cleanup ----------
async def on_startup(app):
    print("[Supabase] Creating HTTP client session")
    app["http_client"] = ClientSession()

async def on_cleanup(app):
    print("[Supabase] Closing HTTP client session")
    await app["http_client"].close()

# ---------- Utility ----------
def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

# 🟢 FIX: Updated to run rosboard as a module
def run_rosboard_backend():
    if is_port_in_use(8899):
        print("[ROSBoard] ⚠️ Backend already running on port 8899, skipping spawn.")
        return
    
    print("[ROSBoard] 🚀 Launching backend on port 8899...")
    
    # Get the project root directory (which is the parent of BASE_DIR)
    # This is /home/bassam279/rosboard/
    project_root = BASE_DIR.parent 
    
    # Command to run rosboard.py as a module from the project root
    # This ensures all package imports (like 'from rosboard.serialization') work
    cmd = ["python3", "-m", "rosboard.rosboard", "--port", "8899"]
    
    # Run the command from the project root directory
    print(f"[ROSBoard] Running command: `{' '.join(cmd)}` in `{project_root}`")
    subprocess.Popen(cmd, cwd=project_root)

# ---------- Login ----------
async def login_page(request):
    login_path = WEB_DIR / "login.html"
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")      # Correct form field
        pwd = data.get("password")     # Correct form field

        print(f"[Login Debug] Attempting Supabase login for {email}")

        # Use the app's shared http_client session
        login_payload = {"email": email, "password": pwd}
        async with request.app["http_client"].post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers={"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"},
            json=login_payload
        ) as resp:
            result = await resp.json()
            print(f"[Supabase] Auth result: {result}")

            if resp.status == 200 and "access_token" in result:
                session_data = await get_session(request)
                session_data["user"] = {"email": email}
                print(f"[Login] ✅ {email} logged in successfully.")
                # Redirect to /redirect.html
                raise web.HTTPFound("/redirect.html")
            else:
                print(f"[Login] ❌ Invalid credentials for {email}.")
                return web.Response(
                    text="Invalid credentials. Please try again.",
                    content_type='text/html'
                )
    return web.FileResponse(login_path)

# ---------- Logout ----------
async def logout(request):
    session = await get_session(request)
    session.invalidate()
    raise web.HTTPFound("/login")

# 🟢 START: THIS IS THE CORRECTED FUNCTION
async def register_page(request):
    register_path = WEB_DIR / "register.html"
    if request.method == "POST":
        data = await request.post()
        email, password = data.get("email"), data.get("password")
        
        # 🟢 1. GET THE 'ROLE' FROM THE FORM
        role = data.get("role", "user") # Defaults to 'user' if not found
        
        # --- Step 1: Create the user in Supabase Auth ---
        print(f"[Register] Attempting Auth signup for {email} (Role: {role})") # Added role to log
        signup_payload = {"email": email, "password": password}
        auth_status, auth_result = await sb_auth_post(
            request.app["http_client"], "signup", signup_payload
        )
        
        if auth_status not in [200, 201]:
            # Signup failed (e.g., user exists, weak password)
            error_msg = auth_result.get('msg', 'Authentication signup failed')
            print(f"[Register] ❌ Auth signup failed: {error_msg}")
            return web.Response(text=f"Registration failed: {error_msg}", status=auth_status)
        
        print(f"[Register] ✅ Auth user created: {email}")

        # 🟢 FIX: Get the ID more robustly
        auth_user_id = None
        if 'id' in auth_result:
            auth_user_id = auth_result.get('id') # ID is at the top level
        elif 'user' in auth_result and 'id' in auth_result['user']:
            auth_user_id = auth_result['user'].get('id') # ID is nested in auth_result['user']

        if not auth_user_id:
            # We can't proceed without an ID
            print(f"[Register] ❌ CRITICAL: Could not get user ID from Supabase auth result: {auth_result}")
            # Clean up the auth user we just created
            # (This part is optional but good practice)
            return web.Response(text="Registration failed (could not get user ID)", status=500)
        # 🟢 END FIX

        # --- Step 2: Create the user's public profile in the 'profiles' table ---
        
        # 🟢 2. USE THE 'ROLE' VARIABLE IN THE PAYLOAD
        profile_payload = {"email": email, "role": role, "id": auth_user_id}
        
        profile_status, profile_created = await sb_post(
            request.app["http_client"], "profiles", profile_payload
        )
        
        if profile_status in (200, 201):
            print(f"[Register] ✅ Profile created for: {email} as {role}")
            raise web.HTTPFound("/login")
        else:
            # This is a problem: auth user was created but profile failed.
            print(f"[Register] ❌ Profile creation failed: {profile_created}")
            # In a real app, you might want to delete the auth user here to clean up
            return web.Response(text="Registration failed (profile creation error)", status=500)
            
    return web.FileResponse(register_path)
# 🟢 END: THIS IS THE CORRECTED FUNCTION


# ---------- Forgot Password ----------
async def forgot_password_page(request):
    forgot_path = WEB_DIR / "forgot_password.html"
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        
        # 🟢 FIX: This should call the Auth 'recover' endpoint, not query profiles
        print(f"[ForgotPassword] Initiating password recovery for {email}")
        payload = {"email": email}
        status, result = await sb_auth_post(
            request.app["http_client"], "recover", payload
        )

        if status == 200:
            print(f"[ForgotPassword] ✅ Recovery email sent to {email}")
            return web.Response(text="If your email is in our system, a password reset link has been sent.", status=200)
        else:
            # Don't tell the user if the email was found or not (security)
            print(f"[ForgotPassword] ❌ Recovery failed or email not found: {result}")
            return web.Response(text="If your email is in our system, a password reset link has been sent.", status=200)
            
    return web.FileResponse(forgot_path)

# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    path = request.path
    if path.startswith(("/login", "/register", "/forgot", "/static", "/logout", "/redirect.html")):
        return await handler(request)
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")
    return await handler(request)

# ---------- Main ----------
def main():
    print("[ROSBoard] 🔧 Starting login + admin server...")

    if SPAWN_BACKEND:
        threading.Thread(target=run_rosboard_backend, daemon=True).start()
    else:
        print("[ROSBoard] ⚙️ Running in main mode — backend not spawned to avoid recursion.")

    app = web.Application(middlewares=[
        aiohttp_session.session_middleware(SimpleCookieStorage()),
        require_login_middleware
    ])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Routes
    app.router.add_get("/", login_page)
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_page)
    app.router.add_get("/logout", logout)
    app.router.add_get("/register", register_page)
    app.router.add_post("/register", register_page)
    app.router.add_get("/forgot-password", forgot_password_page)
    app.router.add_post("/forgot-password", forgot_password_page)
    app.router.add_get("/redirect.html", lambda request: web.FileResponse(WEB_DIR / "redirect.html"))
    app.router.add_static("/static/", path=str(WEB_DIR / "static"), name="static")

    print("[ROSBoard] ✅ Server running at: http://localhost:8888")
    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()
