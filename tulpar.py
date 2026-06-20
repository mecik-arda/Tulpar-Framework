import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tulpar.main import ana_fonksiyon  # noqa: E402

if __name__ == "__main__":
    ana_fonksiyon()
