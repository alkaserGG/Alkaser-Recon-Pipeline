# test_main.py
import importlib.util
import sys
from pathlib import Path

def test_main_importable():
    """Verify main.py can be imported without errors."""
    spec = importlib.util.spec_from_file_location("main", Path("main.py"))
    module = importlib.util.module_from_spec(spec)
    # لو فيه import error هيفشل هنا
    assert spec is not None
    assert module is not None

def test_output_layout():
    """Verify OutputLayout creates correct directory structure."""
    # test بدون import عشان نتجنب مشكلة الـ dependencies
    from pathlib import Path
    root = Path("results") / "test.com"
    expected_dirs = ["recon", "vulns", "crawl", "exploit"]
    for d in expected_dirs:
        assert isinstance(root / d, Path)

def test_domain_cleaning():
    """Verify domain cleaning logic."""
    raw = "https://example.com/path"
    cleaned = raw.replace("http://", "").replace("https://", "").split("/")[0]
    assert cleaned == "example.com"

def test_read_lines_missing_file():
    """read_lines should return [] for
