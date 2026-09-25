"""密码哈希与会话/CSRF 随机令牌生成（纯函数，可单测）。"""

from __future__ import annotations

import hashlib
import hmac
import os

PBKDF2_ROUNDS = 200_000
HASH_ALGO = "sha256"


def new_salt() -> str:
    """生成 16 字节随机盐，十六进制编码。"""
    return os.urandom(16).hex()


def new_token(nbytes: int = 32) -> str:
    """生成密码学安全的不透明随机令牌，十六进制编码。"""
    return os.urandom(nbytes).hex()


def hash_password(password: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 派生密码哈希。"""
    derived = hashlib.pbkdf2_hmac(
        HASH_ALGO,
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ROUNDS,
    )
    return derived.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """恒定时间比较，避免时序侧信道。"""
    candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, expected_hash)
