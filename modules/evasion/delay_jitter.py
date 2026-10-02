"""delay_jitter v2 — human-like request pacing (Poisson + burst + profiles).

API для модулей:
    from modules.evasion.delay_jitter import wait, get_profile
    wait(profile="normal")
"""
import time
import random


PROFILES = {
    "aggressive": {"mean_delay": 0.3, "burst_size": 10, "burst_pause": (2.0, 5.0),
                   "long_pause_chance": 0.05, "long_pause_range": (5.0, 15.0)},
    "normal":     {"mean_delay": 1.5, "burst_size": 3,  "burst_pause": (5.0, 15.0),
                   "long_pause_chance": 0.1,  "long_pause_range": (15.0, 45.0)},
    "careful":    {"mean_delay": 4.0, "burst_size": 5,  "burst_pause": (10.0, 25.0),
                   "long_pause_chance": 0.15, "long_pause_range": (30.0, 90.0)},
    "stealth":    {"mean_delay": 8.0, "burst_size": 10,  "burst_pause": (20.0, 60.0),
                   "long_pause_chance": 0.2,  "long_pause_range": (60.0, 180.0)},
    "burst":      {"mean_delay": 0.15, "burst_size": 20, "burst_pause": (20.0, 60.0),
                   "long_pause_chance": 0.05, "long_pause_range": (30.0, 90.0)},
}


def get_profile(name="normal"):
    return PROFILES.get(name, PROFILES["normal"])


class _State:
    def __init__(self):
        self.profile_name = "normal"
        self.profile = get_profile("normal")
        self.burst_count = 0

    def reset(self, name):
        self.profile_name = name
        self.profile = get_profile(name)
        self.burst_count = 0


_state = _State()


def _poisson_delay(mean):
    return random.expovariate(1.0 / mean) if mean > 0 else 0.1


def wait(profile=None):
    if profile:
        _state.reset(profile)
    cfg = _state.profile
    delay = _poisson_delay(cfg["mean_delay"])

    # burst — только если burst_size > 1 (иначе это отключение burst-режима)
    if cfg["burst_size"] > 1:
        _state.burst_count += 1
        if _state.burst_count >= cfg["burst_size"]:
            delay = random.uniform(*cfg["burst_pause"])
            _state.burst_count = 0

    # длинная пауза — с настроенной вероятностью
    if random.random() < cfg["long_pause_chance"]:
        delay = random.uniform(*cfg["long_pause_range"])

    delay = max(0.05, delay)
    time.sleep(delay)
    return delay


class DelayJitter:
    def run(self, session, logger):
        profile_name = "normal"
        for x in getattr(session, "extra", []) or []:
            if x.startswith("jitter="):
                profile_name = x[7:].strip()

        cfg = get_profile(profile_name)
        _state.reset(profile_name)

        print(f"[delay_jitter v2] profile: {profile_name}")
        print(f"[delay_jitter v2] config: mean={cfg['mean_delay']}s burst={cfg['burst_size']}")
        print(f"[delay_jitter v2]          burst_pause={cfg['burst_pause']} long_pause_chance={cfg['long_pause_chance']}")

        N = 15
        delays = []
        print()
        print(f"[delay_jitter v2] generating {N} delays (no actual requests):")
        for i in range(N):
            c = _state.profile
            d = _poisson_delay(c["mean_delay"])
            kind = "poisson"
            # burst только если burst_size > 1
            if c["burst_size"] > 1:
                _state.burst_count += 1
                if _state.burst_count >= c["burst_size"]:
                    d = random.uniform(*c["burst_pause"])
                    _state.burst_count = 0
                    kind = "burst"
            if random.random() < c["long_pause_chance"]:
                d = random.uniform(*c["long_pause_range"])
                kind = "long"
            delays.append(d)
            print(f"  #{i+1:2d}  {d:6.2f}s  [{kind}]")

        avg = sum(delays) / len(delays) if delays else 0
        mn, mx = (min(delays), max(delays)) if delays else (0, 0)

        print()
        print(f"[delay_jitter v2] avg={avg:.2f}s min={mn:.2f}s max={mx:.2f}s")

        logger.info("delay_jitter",
                    profile=profile_name, avg=round(avg, 2), n=N)

        return {"profile": profile_name, "delays": delays,
                "avg": avg, "min": mn, "max": mx}
