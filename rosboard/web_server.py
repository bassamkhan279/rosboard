from aiohttp import web
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session
import pathlib
import json
import os

# Path to this file's folder
BASE_DIR = pathlib.Path(__file__).parent
WEB_DIR = BASE_DIR / "web"
USERS_FILE = BASE_DIR / "users.json"

# -------------------------------
# Load users from JSON file
# -------------------------------
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

# -------------------------------
# Save users to JSON file
# -------------------------------
def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# -------------------------------
# Login page handler
# -------------------------------
async def login_page(request):
    login_path = WEB_DIR / "login.html"

    if request.method == "POST":
        data = await request.post()
        username = data.get("username")
        password = data.get("password")

        users = load_users()
        if username in users and users[username] == password:
            session = await get_session(request)
            session["user"] = username
            raise web.HTTPFound("/")
        else:
            return web.Response(text="Invalid username or password. <a href='/login'>Try again</a>", content_type="text/html")

    return web.FileResponse(login_path)

# -------------------------------
# Protected home page
# -------------------------------
async def home_page(request):
    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")
    return web.Response(text=f"Hello, {session['user']}! You are logged in.", content_type="text/html")

# -------------------------------
# Middleware: require login
# -------------------------------
@web.middleware
async def require_login_middleware(request, handler):
    session = await get_session(request)
    if request.path not in ["/login"] and "user" not in session:
        raise web.HTTPFound("/login")
    return await handler(request)

# -------------------------------
# Create and run the app
# -------------------------------
def create_app():
    app = web.Application(middlewares=[require_login_middleware])
    aiohttp_session.setup(app, SimpleCookieStorage())

    app.router.add_route("GET", "/", home_page)
    app.router.add_route("GET", "/login", login_page)
    app.router.add_route("POST", "/login", login_page)
    return app

if __name__ == "__main__":
    app = create_app()
    print("🚀 Server running at http://localhost:8888/login")
    web.run_app(app, host="0.0.0.0", port=8888)
