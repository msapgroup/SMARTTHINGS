"""GODSEYE application entry point.

Loads the core FastAPI app plus the native integration/tool API. Keeping the
integration router here lets the existing app/main.py remain stable while
adding NetAlertX-style functionality without Docker or a second web server.
"""
from .main import app
from .integrations import router as integrations_router

app.include_router(integrations_router)

if __name__ == "__main__":
    import os
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
