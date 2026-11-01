from pathlib import Path


def advisory_directory() -> Path:
    """Use packaged data in both wheels and editable installs."""
    return Path(__file__).with_name("advisories")
