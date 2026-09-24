# core/loader.py — dynamic module discovery
import importlib.util
import inspect
from pathlib import Path

MODULES_ROOT = Path(__file__).parent.parent / "modules"

class ModuleLoader:
    def __init__(self, root=MODULES_ROOT): self.root = root
    def list_category(self, category):
        cdir = self.root / category
        if not cdir.is_dir(): return {}
        return {f.stem: self._peek_desc(f) for f in sorted(cdir.glob("*.py")) if not f.name.startswith("_")}
    def _peek_desc(self, path):
        try:
            for line in path.read_text(encoding="utf-8").splitlines()[:25]:
                s = line.strip()
                if s.startswith('"""'): return s.strip('"').strip()
                if s.startswith("# "): return s[2:].strip()
        except Exception: pass
        return ""
    def load(self, category, name):
        mod_path = self.root / category / f"{name}.py"
        if not mod_path.is_file(): return None
        spec = importlib.util.spec_from_file_location(f"omni_mod_{category}_{name}", mod_path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if hasattr(obj,"run") and obj.__module__ == module.__name__:
                return obj()
        return None
