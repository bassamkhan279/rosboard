import asyncio
from aiohttp import web
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, get_session
import pathlib

__version__ = "1.3.1"

# Path to web folder (create it if not there)
webdir = pathlib.Path(__file__).parent / "web"

# ---------- Login Page ----------
async def login_page(request):
    login_path = webdir / "login.html"
    if request.method == "POST":
        data = await request.post()
        username = data.get("username")
        password = data.get("password")
        # Example credentials
        if username == "admin@example.com" and password == "1234":
            session = await get_session(request)
            session["user"] = username
            raise web.HTTPFound("/")
        else:
            return web.Response(text="Invalid username or password", status=401)
    return web.FileResponse(login_path)

# ---------- Middleware (forces login) ----------
@web.middleware
async def require_login_middleware(request, handler):
    session = await get_session(request)
    if request.path not in ["/login", "/static"] and "user" not in session:
        raise web.HTTPFound("/login")
    return await handler(request)

# ---------- Main Entry ----------
def main():
    app = web.Application(middlewares=[require_login_middleware])
    aiohttp_session.setup(app, SimpleCookieStorage())

    app.router.add_route("GET", "/login", login_page)
    app.router.add_route("POST", "/login", login_page)

    # Static files (optional)
    app.router.add_static("/static/", path=str(webdir / "static"), name="static")

    # Placeholder dashboard (you’ll replace this later with ROSBoard dashboard)
    async def index(request):
        return web.Response(text="<h1>Welcome to ROSBoard Dashboard!</h1>")

    app.router.add_route("GET", "/", index)

    web.run_app(app, host="0.0.0.0", port=8888)

if __name__ == "__main__":
    main()
