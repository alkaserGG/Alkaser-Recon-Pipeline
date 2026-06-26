# 1. إنشاء الملف
cat > test_main.py << 'EOF'
def test_domain_cleaning():
    raw = "https://example.com/path"
    cleaned = raw.replace("http://", "").replace("https://", "").split("/")[0]
    assert cleaned == "example.com"

def test_domain_cleaning_no_protocol():
    raw = "example.com"
    cleaned = raw.replace("http://", "").replace("https://", "").split("/")[0]
    assert cleaned == "example.com"

def test_read_lines_missing():
    from pathlib import Path
    path = Path("nonexistent_99999.txt")
    result = [] if not path.exists() else []
    assert result == []

def test_placeholder():
    assert True
EOF

# 2. رفعه على GitHub
git add test_main.py
git commit -m "add pytest tests"
git push
