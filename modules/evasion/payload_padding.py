"""payload_padding — pad payloads with random noise to evade signature length heuristics"""
import random, string

def pad_prefix(n): return "".join(random.choices(string.ascii_letters, k=n))
def pad_suffix(n): return "".join(random.choices(string.ascii_letters, k=n))
def comment_pad(payload, n=20):
    return f"/*{pad_prefix(n)}*/" + payload + f"/*{pad_suffix(n)}*/"
def null_pad(payload, n=10):
    return payload + "%00" * n

class PayloadPadding:
    def run(self, session, logger):
        payload = session.target
        print(f"[payload_padding] input: {payload[:80]}")
        results = {
            "prefix_32":  pad_prefix(32) + payload,
            "suffix_32":  payload + pad_suffix(32),
            "both_64":    pad_prefix(32) + payload + pad_suffix(32),
            "comment":    comment_pad(payload),
            "null":       null_pad(payload, 5),
        }
        for name, out in results.items():
            print(f"  {name:12s} ({len(out)} chars)")
        return {"results": results}
