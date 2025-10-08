import threading
import subprocess
from aiohttp import web
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session
import pathlib

# Path to the web folder (where login.html is)
webdir = pathlib.Path(__file__).parent / "web"
# Path to ROSBoard's main HTML dashboard
rosboard_html = pathlib.Path(__file__).parent / "html" / "index.html"

# ---------- Login Page ----------
async def login_page(request):
    login_path = webdir / "login.html"
    if request.method == "POST":
        data = await request.post()
        user = data.get("username")
        pwd = data.get("password")
        # Hardcoded login credentials
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
    session = await get_session(request)
    if request.path not in ["/login", "/static"] and "user" not in session:
        raise web.HTTPFound("/login")
    return await handler(request)

# ---------- Dashboard ----------
async def dashboard(request):
    # Return the actual ROSBoard dashboard (index.html)
    return web.FileResponse(rosboard_html)

# ---------- Main ----------
def main():
    app = web.Application(middlewares=[require_login_middleware])
    aiohttp_session.setup(app, SimpleCookieStorage())
    app.router.add_route("GET", "/login", login_page)
    app.router.add_route("POST", "/login", login_page)
    app.router.add_route("GET", "/dashboard", dashboard)
    app.router.add_static("/static/", path=str(webdir / "static"), name="static")

    print("[ROSBoard] Login server running on http://localhost:8888")
    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()
