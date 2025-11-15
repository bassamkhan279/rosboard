#!/usr/bin/env python3
import os
import threading
import subprocess
import pathlib
import json
import sys
import socket
import asyncio
import time
import aiohttp
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

# ---------- Supabase Config (Unmodified) ----------
SUPABASE_URL = "https://pxlbmyygaiqevnbcrnmj.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjMxMDU3NjUsImV4cCI6MjA3ODQ2NTc2NX0.dZGlpzwumKk2RkcuBr311UaxsT28hUu9fD027Qj8jhA"
SUPABASE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB4bGJteXlnYWlxZXZuYmNybm1qIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzEwNTc2NSwiZXhwIjoyMDc4NDY1NzY1fQ._-WhtBPNPhuVwap51TK4JL29EvhU9XELErT4dMhhr5o"

POSTGREST_BASE = f"{SUPABASE_URL}/rest/v1"
AUTH_BASE = f"{SUPABASE_URL}/auth/v1"

# --- Helper HTTP functions (Unmodified) ---
def _supabase_headers():
    return {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

def _auth_headers(jwt=None):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json"
    }
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    return headers

async def sb_auth_post(session: ClientSession, path: str, payload: dict):
    url = f"{AUTH_BASE}/{path}"
    async with session.post(url, headers=_auth_headers(), json=payload) as resp:
        try:
            data = await resp.json()
        except Exception:
            data = {"raw": await resp.text()}
        return resp.status, data
        
async def sb_admin_auth_post(session: ClientSession, path: str, payload: dict):
    url = f"{AUTH_BASE}/{path}"
    headers = {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}",
        "Content-Type": "application/json"
    }
    async with session.post(url, headers=headers, json=payload) as resp:
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

async def sb_patch(session: ClientSession, path: str, payload: dict, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.patch(url, headers=_supabase_headers(), params=params, json=payload) as resp:
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"raw": await resp.text()}

async def sb_delete(session: ClientSession, path: str, params: dict = None):
    url = f"{POSTGREST_BASE}/{path}"
    async with session.delete(url, headers=_supabase_headers(), params=params) as resp:
        if resp.status == 204: # 204 No Content is success for delete
            return resp.status, {"status": "deleted"}
        try:
            return resp.status, await resp.json()
        except Exception:
            return resp.status, {"raw": await resp.text()}

# ---------- App startup / cleanup (Unmodified) ----------
async def on_startup(app):
    print("[Supabase] Creating HTTP client session")
    app["http_client"] = ClientSession()

async def on_cleanup(app):
    print("[Supabase] Closing HTTP client session")
    await app["http_client"].close()

# ---------- Utility (Unmodified) ----------
def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

#
# ### MODIFIED (STABILIZED) ### - Combined Publisher Spawner
#
def run_publisher_nodes():
    if not os.environ.get("ROS_DISTRO"):
        print("[Publishers] ⚠️ ROS environment not sourced, skipping node spawn.")
        return
    
    # 🌟 CRITICAL FIX: Add this line back!
    env = os.environ.copy() 

    # --- 1. Launch the Camera Node ---
    print("[Camera Node] 🚀 Launching Camera Publisher...")
    camera_cmd = ["rosrun", "usb_cam", "usb_cam_node"] 
    
    try:
        subprocess.Popen(camera_cmd, env=env) # Now 'env' is defined
        print("[Camera Node] ✅ Camera node started.")
    except Exception as e:
        # ... (rest of the block)
        print(f"[Camera Node] ❌ Failed to start camera node. Error: {e}")

    # --- 2. Launch the Battery Monitor Node ---
    print("[Battery Node] 🚀 Launching Battery Monitor...")
    # ✅ UNCOMMENT THIS:
    battery_cmd = ["rosrun", "your_robot_package", "battery_monitor_node.py"] 
    
    try:
        subprocess.Popen(battery_cmd, env=env)
        print("[Battery Node] ✅ Battery monitor started.")
    except Exception as e:
        print(f"[Battery Node] ❌ Failed to start battery monitor. Error: {e}")

#
# ------------------------------------------------
#

# ---------- ROSBoard Backend Spawner (Unmodified) ----------
def run_rosboard_backend():
    if is_port_in_use(8899):
        print("[ROSBoard] ⚠️ Backend already running on port 8899, skipping spawn.")
        return
    
    print("[ROSBoard] 🚀 Launching backend on port 8899...")
    
    # project_root is /home/bassam279/rosboard
    project_root = BASE_DIR.parent 
    
    # This is the correct command to run the "rosboard.py" module
    cmd = ["python3", "-m", "rosboard.rosboard", "--port", "8899", "--host", "0.0.0.0"]

    # Create a copy of the current environment for the subprocess
    env = os.environ.copy()
    
    # Add the project root to the PYTHONPATH
    current_pythonpath = env.get('PYTHONPATH', '')
    env['PYTHONPATH'] = f"{project_root}:{current_pythonpath}"
    
    print(f"[ROSBoard] Running command: `{' '.join(cmd)}` in `{project_root}` with modified PYTHONPATH")
    
    # Run the command with the new, corrected environment
    subprocess.Popen(cmd, cwd=project_root, env=env)
#
# ------------------------------------------------
#

# ---------- ROSBoard Proxy (Unmodified) ----------
async def rosboard_proxy(request):
    client_session = request.app["http_client"]
    path = request.path_qs
    
    if path.startswith("/rosboard"):
        path = path[len("/rosboard"):]
    if not path:
        path = "/"

    http_target_url = f"http://localhost:8899{path}"

    is_websocket = 'upgrade' in request.headers.get('connection', '').lower() and \
                     'websocket' in request.headers.get('upgrade', '').lower()

    if is_websocket:
        print(f"[Rosboard Proxy] WebSocket request detected for {path}")
        ws_target_url = http_target_url.replace("http://", "ws://")
        
        ws_response = web.WebSocketResponse()
        await ws_response.prepare(request)
        
        print(f"[Rosboard Proxy] Connecting to backend websocket: {ws_target_url}")
        try:
            async with client_session.ws_connect(ws_target_url) as ws_backend:
                print("[Rosboard Proxy] ✅ WebSocket connection established.")
                
                async def forward(ws_from, ws_to):
                    async for msg in ws_from:
                        if ws_to.closed:
                            break
                        
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            await ws_to.send_str(msg.data)
                        elif msg.type == aiohttp.WSMsgType.BINARY:
                            await ws_to.send_bytes(msg.data)
                        elif msg.type == aiohttp.WSMsgType.CLOSED or msg.type == aiohttp.WSMsgType.ERROR:
                            await ws_to.close() 
                            break 
                
                await asyncio.gather(
                    forward(ws_response, ws_backend),
                    forward(ws_backend, ws_response)
                )
        except Exception as e:
            print(f"[Rosboard Proxy] ❌ WebSocket backend connection failed: {e}")
            pass
        
        print("[Rosboard Proxy] WebSocket connection closed.")
        return ws_response

    else: 
        if not path.startswith(("/js/", "/css/", "/fonts/")):
            print(f"[Rosboard Proxy] HTTP request for: {http_target_url}")
            
        try:
            async with client_session.request(
                request.method,
                http_target_url,
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
            print(f"[Rosboard Proxy] ❌ HTTP backend connection failed: {e}")
            return web.Response(text="Rosboard backend is not reachable.", status=502)

# ---------- Login (Unmodified) ----------
async def login_page(request):
    login_path = WEB_DIR / "login.html"
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        pwd = data.get("password")

        print(f"[Login Debug] Attempting Supabase login for {email}")

        login_payload = {"email": email, "password": pwd}
        async with request.app["http_client"].post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers={"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"},
            json=login_payload
        ) as resp:
            result = await resp.json()
            
            if resp.status != 200:
                print(f"[Login] ❌ Auth failed: {result.get('error_description', 'Invalid credentials')}")
                return web.Response(text="Invalid credentials. Please try again.", content_type='text/html')

            print(f"[Login] Auth success. Fetching profile for {email}...")
            params = {"email": f"eq.{email}", "select": "role,id"}
            status, profile_data = await sb_get(request.app["http_client"], "profiles", params=params)
            
            role = "user" # Default role
            user_id = None
            if status == 200 and profile_data:
                role = profile_data[0].get("role", "user")
                user_id = profile_data[0].get("id")
                print(f"[Login] Profile found. Role: {role}")
            else:
                print(f"[Login] ⚠️ No profile found for {email}, defaulting to 'user' role.")

            session_data = await get_session(request)
            session_data["user"] = {"email": email, "role": role, "id": user_id}
            
            print(f"[Login] ✅ {email} logged in successfully as {role}.")
            # REDIRECT to the intermediary page
            raise web.HTTPFound("/redirect.html")

    return web.FileResponse(login_path)

# -------------------------------------------------------------
# ### NEW/MODIFIED ### - SECURE PAGE HANDLERS (Unmodified)
# -------------------------------------------------------------

async def index_page(request):
    """Serves the index.html page only to logged-in users."""
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")
    # Redirect to the ROSBoard proxied path
    raise web.HTTPFound("/rosboard/index.html")

async def camera_page(request):
    """Serves the camera.html page only to logged-in users."""
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")
    # Redirect to the ROSBoard proxied path
    raise web.HTTPFound("/rosboard/camera.html") # <--- MODIFIED

async def odom_page(request):
    """Serves the odom.html page only to logged-in users."""
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")
    # Redirect to the ROSBoard proxied path
    raise web.HTTPFound("/rosboard/odom.html")

# --- Logout, Register, Forgot Password, Admin, Profile, API Endpoints (Unmodified) ---
async def logout(request):
    session = await get_session(request)
    session.invalidate()
    print("[Logout] User logged out.")
    raise web.HTTPFound("/login")

async def register_page(request):
    register_path = WEB_DIR / "register.html"
    if request.method == "POST":
        data = await request.post()
        email, password = data.get("email"), data.get("password")
        role = data.get("role", "user") 
        
        print(f"[Register] Attempting Auth signup for {email} (Role: {role})")
        signup_payload = {"email": email, "password": password}
        auth_status, auth_result = await sb_auth_post(
            request.app["http_client"], "signup", signup_payload
        )
        
        if auth_status not in [200, 201]:
            error_msg = auth_result.get('msg', 'Authentication signup failed')
            print(f"[Register] ❌ Auth signup failed: {error_msg}")
            return web.Response(text=f"Registration failed: {error_msg}", status=auth_status)
        
        print(f"[Register] ✅ Auth user created: {email}")

        auth_user_id = None
        if 'id' in auth_result:
            auth_user_id = auth_result.get('id')
        elif 'user' in auth_result and 'id' in auth_result['user']:
            auth_user_id = auth_result['user'].get('id')

        if not auth_user_id:
            print(f"[Register] ❌ CRITICAL: Could not get user ID from Supabase auth result: {auth_result}")
            return web.Response(text="Registration failed (could not get user ID)", status=500)
        
        profile_payload = {"email": email, "role": role, "id": auth_user_id}
        
        profile_status, profile_created = await sb_post(
            request.app["http_client"], "profiles", profile_payload
        )
        
        if profile_status in (200, 201):
            print(f"[Register] ✅ Profile created for: {email} as {role}")
            raise web.HTTPFound("/login")
        else:
            print(f"[Register] ❌ Profile creation failed: {profile_created}")
            return web.Response(text="Registration failed (profile creation error)", status=500)
            
    return web.FileResponse(register_path)

async def forgot_password_page(request):
    forgot_path = WEB_DIR / "forgot_password.html"
    if request.method == "POST":
        data = await request.post()
        email = data.get("email")
        
        print(f"[ForgotPassword] Initiating password recovery for {email}")
        payload = {"email": email}
        status, result = await sb_auth_post(
            request.app["http_client"], "recover", payload
        )

        if status == 200:
            print(f"[ForgotPassword] ✅ Recovery email sent to {email}")
            return web.Response(text="If your email is in our system, a password reset link has been sent.", status=200)
        else:
            print(f"[ForgotPassword] ❌ Recovery failed or email not found: {result}")
            return web.Response(text="If your email is in our system, a password reset link. Please check your spam folder.", status=200)
            
    return web.FileResponse(forgot_path)

async def require_admin(request):
    """Helper function to protect admin routes."""
    session = await get_session(request)
    user = session.get("user")
    if not user or user.get("role") != "admin":
        print(f"[Security] ❌ Admin access denied for user: {user.get('email')}")
        raise web.HTTPForbidden(text="You must be an admin to access this page.")
    print(f"[Security] ✅ Admin access granted for: {user.get('email')}")
    return user

async def get_user_session(request):
    """API endpoint for frontend to check who is logged in."""
    session = await get_session(request)
    if "user" in session:
        return web.json_response(session["user"])
    return web.json_response({"error": "Not logged in"}, status=401)

async def admin_page(request):
    """Serves the admin.html page, but only to admins."""
    await require_admin(request) # Protect this page
    admin_path = WEB_DIR / "admin.html"
    return web.FileResponse(admin_path)

async def get_users(request):
    """API for admins to get a list of all users."""
    await require_admin(request)
    params = {"select": "id,email,role"} # Get all users
    status, data = await sb_get(request.app["http_client"], "profiles", params=params)
    if status == 200:
        return web.json_response(data)
    return web.json_response({"error": "Failed to fetch users"}, status=status)

async def admin_create_user(request):
    """API for an admin to create a new user."""
    await require_admin(request)
    data = await request.json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")

    if not email or not password:
        return web.json_response({"error": "Email and password are required"}, status=400)
    
    print(f"[Admin] Attempting to create auth user for {email}")
    auth_payload = {
        "email": email, 
        "password": password,
        "email_confirm": True # Auto-confirm the email
    }
    auth_status, auth_result = await sb_admin_auth_post(
        request.app["http_client"], "admin/users", auth_payload
    )

    if auth_status not in [200, 201]:
        error_msg = auth_result.get('msg', 'Auth user creation failed')
        print(f"[Admin] ❌ Auth user creation failed: {error_msg}")
        return web.json_response({"error": f"Auth user creation failed: {error_msg}"}, status=auth_status)
    
    print(f"[Admin] ✅ Auth user created: {email}")
    auth_user_id = auth_result.get('id')

    if not auth_user_id:
        print(f"[Admin] ❌ CRITICAL: Could not get ID from auth result: {auth_result}")
        return web.json_response({"error": "Could not get user ID from auth result"}, status=500)

    profile_payload = {"email": email, "role": role, "id": auth_user_id}
    profile_status, profile_created = await sb_post(
        request.app["http_client"], "profiles", profile_payload
    )
    
    if profile_status in (200, 201):
        print(f"[Admin] ✅ Profile created for: {email} as {role}")
        return web.json_response(profile_created[0]) # Return the new user object
    else:
        print(f"[Admin] ❌ Profile creation failed: {profile_created}")
        return web.json_response({"error": "Profile creation failed"}, status=500)

async def update_user_role(request):
    """API for admins to update a user's role."""
    await require_admin(request)
    user_id = request.match_info["id"]
    data = await request.json()
    new_role = data.get("role")

    if new_role not in ["user", "admin"]:
        return web.json_response({"error": "Invalid role specified"}, status=400)

    params = {"id": f"eq.{user_id}"}
    payload = {"role": new_role}
    
    status, res = await sb_patch(request.app["http_client"], "profiles", payload, params=params)
    
    if status in [200, 204]:
        print(f"[Admin] Updated role for user {user_id} to {new_role}")
        return web.json_response({"status": "updated"})
    return web.json_response({"error": "Failed to update role", "details": res}, status=status)

async def delete_user(request):
    """API for admins to delete a user."""
    await require_admin(request)
    user_id = request.match_info["id"]
    
    url = f"{AUTH_BASE}/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}"
    }
    
    async with request.app["http_client"].delete(url, headers=headers) as resp:
        if resp.status == 200:
            print(f"[Admin] 🗑️ Deleted user {user_id} from auth.")
            return web.json_response({"status": "deleted"})
        else:
            print(f"[Admin] ❌ Failed to delete auth user {user_id}: {await resp.text()}")
            return web.json_response({"error": "Failed to delete user"}, status=resp.status)

async def profile_page(request):
    """Serves the simple profile.html page to any logged-in user."""
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")
    return web.FileResponse(WEB_DIR / "profile.html")

async def change_own_password(request):
    """API for a logged-in user to change their OWN password."""
    session = await get_session(request)
    user = session.get("user")
    if not user:
        return web.json_response({"error": "Not authenticated"}, status=401)

    data = await request.json()
    new_password = data.get("password")

    if not new_password or len(new_password) < 6:
        return web.json_response({"error": "Password must be at least 6 characters"}, status=400)

    user_id = user.get("id")
    url = f"{AUTH_BASE}/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}"
    }
    payload = {"password": new_password}

    async with request.app["http_client"].put(url, headers=headers, json=payload) as resp:
        if resp.status == 200:
            print(f"[Profile] ✅ User {user.get('email')} changed their password.")
            return web.json_response({"status": "password updated"})
        else:
            print(f"[Profile] ❌ Failed to update password for {user.get('email')}: {await resp.text()}")
            return web.json_response({"error": "Failed to update password"}, status=resp.status)

async def delete_own_account(request):
    """API for a logged-in user to delete their OWN account."""
    session = await get_session(request)
    user = session.get("user")
    if not user:
        return web.json_response({"error": "Not authenticated"}, status=401)

    user_id = user.get("id")
    print(f"[Profile] ⚠️ Deleting user {user.get('email')} (ID: {user_id})...")

    url = f"{AUTH_BASE}/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_ROLE_KEY}"
    }
    
    async with request.app["http_client"].delete(url, headers=headers) as resp:
        if resp.status == 200:
            print(f"[Profile] 🗑️ Deleted user {user_id} from auth.")
            session.invalidate() # Log them out
            return web.json_response({"status": "account deleted"})
        else:
            print(f"[Profile] ❌ Failed to delete auth user {user.get('email')}: {await resp.text()}")
            return web.json_response({"error": "Failed to delete account"}, status=resp.status)

# ---------- Middleware (Unmodified) ----------
@web.middleware
async def require_login_middleware(request, handler):
    path = request.path
    
    public_paths = [
        "/login", "/register", "/forgot-password", "/static", 
        "/logout", "/redirect.html", "/rosboard", 
        "/api/get_session" # This must be public so the page can check!
    ]
    
    if any(path.startswith(p) for p in public_paths):
        return await handler(request)

    session = await get_session(request)
    if "user" not in session:
        if path.startswith("/api/"): 
            return web.json_response({"error": "Not authenticated"}, status=401)
        
        print(f"[Security] No session, redirecting to /login (requested path: {path})")
        raise web.HTTPFound("/login")
    
    return await handler(request)

# ---------- Main (Modified) ----------
def main():
    print("[ROSBoard] 🔧 Starting login + admin server...")

    if SPAWN_BACKEND:
        # ### NEW/MODIFIED ###: Start Camera Node and ROSBoard Backend
        threading.Thread(target=run_publisher_nodes, daemon=True).start() # Starts Camera and Battery
        threading.Thread(target=run_rosboard_backend, daemon=True).start()
        
        # --- ADDED: Wait for the ROSBoard backend to start listening on port 8899 ---
        BACKEND_PORT = 8899
        print(f"[ROSBoard] ⏱️ Waiting for backend to initialize on port {BACKEND_PORT}...")
        
        # Give it up to 10 seconds to start up (adjust if needed)
        for i in range(10): 
            if is_port_in_use(BACKEND_PORT):
                print(f"[ROSBoard] ✅ Backend detected on port {BACKEND_PORT}.")
                break
            print(f"[ROSBoard] Waiting... ({i+1}s)")
            time.sleep(1)
        else:
            print(f"[ROSBoard] ❌ WARNING: Backend failed to start on port {BACKEND_PORT} after 10s.")
        # --- END ADDED BLOCK ---
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
    
    # ### NEW/MODIFIED ###: SECURE APP PAGES
    app.router.add_get("/index.html", index_page)
    app.router.add_get("/camera.html", camera_page)
    app.router.add_get("/odom.html", odom_page)
    
    # ROSBoard Proxy Routes
    app.router.add_route("*", "/rosboard", rosboard_proxy)
    app.router.add_route("*", "/rosboard/{path_info:.*}", rosboard_proxy)
    
    # Admin and Profile Routes
    app.router.add_get("/admin", admin_page)
    app.router.add_get("/profile", profile_page)

    # API Routes
    app.router.add_get("/api/get_session", get_user_session)
    app.router.add_get("/api/users", get_users)
    app.router.add_post("/api/users", admin_create_user) 
    app.router.add_put("/api/users/{id}/role", update_user_role)
    app.router.add_delete("/api/users/{id}", delete_user)

    # Self-serve API Routes
    app.router.add_post("/api/user/password", change_own_password)
    app.router.add_delete("/api/user", delete_own_account)

    app.router.add_static("/static/", path=str(WEB_DIR / "static"), name="static")

    print("[ROSBoard] ✅ Server running at: http://localhost:8888")
    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()

