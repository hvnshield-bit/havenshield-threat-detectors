import sys


def test_importable():
    # Basic smoke test to ensure the module imports
    sys.path.insert(0, "src")
    try:
        import havenshield  # type: ignore
    finally:
        sys.path.pop(0)
