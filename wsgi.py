# wsgi.py
from app import create_app  # adjust import if your factory lives elsewhere
def create_app():
    from app import create_app as factory
    return factory()
# Optional: keep this for local tools that expect `app`
app = create_app()
