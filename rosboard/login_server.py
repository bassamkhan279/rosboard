import threading
import subprocess
from aiohttp import web
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session
import pathlib

# Path to the web folder
webdir = pathlib.Path(__file__).parent / "web"

# ---------- Login Page ----------
async def login_page(request):
    login_path = webdir / "login.html"
    if request.method == "POST":
        data = await request.post()
        user = data.get("username")
        pwd = data.get("password")

        # Dummy credentials
        if user == "admin@example.com" and pwd == "1234":
            session = await get_session(request)
            session["user"] = user
            raise web.HTTPFound("/dashboard")
        else:
            return web.Response(text="Invalid credentials", status=401)

    return web.FileResponse(login_path)

# ---------- Middleware ----------
@web.middleware
async def require_login_middleware(request, handler):
    # Allow access to login and static pages without login
    if request.path.startswith("/login") or request.path.startswith("/static"):
        return await handler(request)

    session = await get_session(request)
    if "user" not in session:
        raise web.HTTPFound("/login")

    return await handler(request)

# ---------- Dashboard ----------
async def dashboard(request):
    # Start ROSBoard dashboard on a different port
    def run_rosboard():
        subprocess.run(["python3", "-m", "rosboard.rosboard", "--port", "8889"])
    threading.Thread(target=run_rosboard, daemon=True).start()

    raise web.HTTPFound("http://localhost:8889")

# ---------- Main ----------
def main():
    app = web.Application(middlewares=[aiohttp_session.session_middleware(SimpleCookieStorage()), require_login_middleware])
    aiohttp_session.setup(app, SimpleCookieStorage())

    app.router.add_route("GET", "/login", login_page)
    app.router.add_route("POST", "/login", login_page)
    app.router.add_route("GET", "/dashboard", dashboard)
    app.router.add_static("/static/", path=str(webdir / "static"), name="static")

    print("[ROSBoard] Login server running on http://localhost:8888")
    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()
