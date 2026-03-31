# redis_store.py
import redis


class RedisStore:
    def __init__(self, host="localhost", port=6379, db=0):
        self.r = redis.Redis(host=host, port=port, db=db, decode_responses=True)

    def ping(self) -> bool:
        try:
            return bool(self.r.ping())
        except Exception:
            return False

    def set_block(self, ip: str, reason: str, ttl: int) -> None:
        self.r.set(f"block:{ip}", reason, ex=ttl)

    def is_blocked(self, ip: str) -> bool:
        return self.r.exists(f"block:{ip}") == 1

    def get_block_reason(self, ip: str):
        return self.r.get(f"block:{ip}")

    def incr_offender(self, ip: str, ttl: int = 300) -> int:
        key = f"offender:{ip}"
        count = self.r.incr(key)
        self.r.expire(key, ttl)
        return count

    def get_offender_count(self, ip: str) -> int:
        val = self.r.get(f"offender:{ip}")
        return int(val) if val else 0

    def count_blocked(self) -> int:
        count = 0
        cursor = 0
        while True:
            cursor, keys = self.r.scan(cursor=cursor, match="block:*", count=500)
            count += len(keys)
            if cursor == 0:
                break
        return count

    def list_blocked_ips(self) -> list[str]:
        ips: list[str] = []
        cursor = 0
        while True:
            cursor, keys = self.r.scan(cursor=cursor, match="block:*", count=500)
            ips.extend(k.split("block:", 1)[1] for k in keys if k.startswith("block:"))
            if cursor == 0:
                break
        return ips