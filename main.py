import uvicorn

from app.routes import create_app, seed_user

app = create_app()
seed_user(app, "alice", "alice-password", {"reader"})
seed_user(app, "admin", "admin-password", {"admin"})

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
