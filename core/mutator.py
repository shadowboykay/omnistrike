# core/mutator.py — URL/param mutator for WAF bypass on block
import urllib.parse


def _case_swap(s):
    import random
    return "".join(c.upper() if random.random() < 0.4 else c.lower() if c.isalpha() else c for c in s)

def _url_enc(s):
    return urllib.parse.quote(s, safe="")

def _double_enc(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def _comment_space(s):
    return s.replace(" ", "/**/")

def _newline_space(s):
    return s.replace(" ", "%0a")

def _tab_space(s):
    return s.replace(" ", "%09")

def _chunk_ws(s):
    import random
    return s.replace(" ", random.choice(["%20", "+", "%09", "%0a", "/**/"]))

def _add_null(s):
    return s + "%00"

def _add_comment(s):
    return s + "/**/"


_MUTATORS = [_case_swap, _url_enc, _double_enc, _comment_space,
             _newline_space, _tab_space, _chunk_ws, _add_null, _add_comment]


def mutate_param(value, n=6):
    """Return up to n mutated variants of a query parameter value."""
    import random
    out = []
    seen = {value}
    for _ in range(n * 3):
        if len(out) >= n:
            break
        f = random.choice(_MUTATORS)
        try:
            v = f(value)
        except Exception:
            continue
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def mutate_url_query(url, n=6):
    """
    Generate URL variants with each query param mutated one at a time.
    Returns a generator: (mutated_url, param_name, mutated_value)
    """
    u = urllib.parse.urlparse(url)
    if not u.query:
        return
    params = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    for name, vals in params.items():
        original = vals[0] if vals else ""
        for variant in mutate_param(original, n=n):
            new_params = {k: (v[0] if v else "") for k, v in params.items()}
            new_params[name] = variant
            new_query = urllib.parse.urlencode(new_params)
            yield (urllib.parse.urlunparse(u._replace(query=new_query)), name, variant)
