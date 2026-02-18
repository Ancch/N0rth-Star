import random
from datetime import datetime

ATTACK_TEMPLATES = [
    "POST /login failed for user admin from {ip}",
    "SQL error near ' OR 1=1 -- at endpoint /api/users",
    "JWT token leaked: {token}",
    "AWS key exposed: AKIA{rand}",
    "password dump: user=admin pass={password}",
    "ddos planning on {target} tonight",
]

def generate_attack_logs(n=10):
    logs = []
    for _ in range(n):
        logs.append({
            "title": "synthetic_attack",
            "author": "simulator",
            "created_at": datetime.utcnow(),
            "url": f"sim://{random.randint(1000,9999)}",
            "text": random.choice(ATTACK_TEMPLATES).format(
                ip=f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
                token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                rand=random.randint(100000,999999),
                password=random.choice(["123456", "admin123", "qwerty"]),
                target=random.choice(["upi_gateway", "telecom_api", "bank_server"])
            )
        })
    return logs
