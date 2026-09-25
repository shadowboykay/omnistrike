"""Test module loader — all modules should load without errors."""
from core.loader import ModuleLoader

CATEGORIES = ["recon","web","bypass","exploit","evasion","c2","post",
              "osint","mobile","cloud","ad","dump"]


def test_all_modules_load():
    loader = ModuleLoader()
    broken = []
    for cat in CATEGORIES:
        mods = loader.list_category(cat)
        for name in mods:
            try:
                m = loader.load(cat, name)
                if not m:
                    broken.append(f"{cat}/{name}")
            except Exception as e:
                broken.append(f"{cat}/{name} ({type(e).__name__})")
    assert not broken, f"Broken modules: {broken}"


def test_categories_have_modules():
    loader = ModuleLoader()
    for cat in CATEGORIES:
        mods = loader.list_category(cat)
        assert len(mods) > 0, f"Category {cat} is empty"
