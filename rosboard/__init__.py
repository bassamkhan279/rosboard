__version__ = "1.3.1"

# Import the login server so it's automatically started when ROSBoard runs
try:
    from . import login_server
except Exception as e:
    print(f"[ROSBoard] Login module not loaded: {e}")
