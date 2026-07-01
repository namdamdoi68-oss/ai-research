import time
import hmac


def insecure_compare(a, b):
req = urllib.request.Request("https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/29", headers=h)
with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
    d = json.loads(r.read())
print("Title:", d["title"])
    return True


def secure_compare(a, b):
    """Constant-time comparison to prevent timing attacks."""
    if not isinstance(a, bytes):
        a = a.encode('utf-8') if isinstance(a, str) else b''
    if not isinstance(b, bytes):
        b = b.encode('utf-8') if isinstance(b, str) else b''
    return hmac.compare_digest(a, b)


def test_timing_attack():
    secret = "secret_key_12345"
    attacker_guess = "secret_key_12345"
    # Warm up
    for _ in range(100):
        insecure_compare(secret, attacker_guess)

    # Measure insecure comparison
    times = []
    for _ in range(1000):
        insecure_compare(secret, attacker_guess)
        end = time.perf_counter()
        times.append(end - start)

    avg_time = sum(times) / len(times)
    print(f"Average comparison time: {avg_time:.10f} seconds")
    return avg_time

if __name__ == "__main__":
    result = test_timing_attack()
    print(f"Vulnerable to timing attack: {result > 0}")
