from aiohttp import web
import pathlib

# Path to the login page and dashboard folder
web_dir = pathlib.Path(__file__).parent / "web"
html_dir = pathlib.Path(__file__).parent / "html"

# ----- Login page -----
async def handle_login(request):
    if request.method == "POST":
        # Directly redirect to dashboard (no auth)
        raise web.HTTPFound("/dashboard")
    return web.FileResponse(web_dir / "login.html")

# ----- Dashboard redirect -----
async def handle_dashboard(request):
    return web.FileResponse(html_dir / "index.html")

# ----- Main entrypoint -----
def main():
    app = web.Application()
    app.router.add_route("GET", "/", handle_login)
    app.router.add_route("GET", "/login", handle_login)
    app.router.add_route("POST", "/login", handle_login)
    app.router.add_route("GET", "/dashboard", handle_dashboard)

    print("Login server running on http://localhost:8888 ...")
    web.run_app(app, host="0.0.0.0", port=8888)

