"""Dev launcher for SecretScope."""
import uvicorn
import os

if __name__ == "__main__":
    port = int(os.environ.get("SECRETSCOPE_PORT", 8077))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
