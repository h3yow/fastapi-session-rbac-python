"""应用入口：创建 FastAPI 应用、装配容器、统一异常响应。"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .container import build_container
from .errors import AppError
from .routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


def create_app() -> FastAPI:
    app = FastAPI(title="Session + RBAC Demo")
    app.state.container = build_container()

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        # 统一拒绝响应体：error.code 可稳定区分原因，message 给出判定依据
        logging.getLogger("http").info(
            "rejected method=%s path=%s code=%s", request.method, request.url.path, exc.code
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    app.include_router(router)
    return app


app = create_app()
