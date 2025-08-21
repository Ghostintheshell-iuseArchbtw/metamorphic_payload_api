import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from payload_generator import random_amsi_bypass


def test_random_amsi_bypass_class_name_consistency():
    # Try repeatedly to trigger technique using a C# helper class
    for _ in range(100):
        snippet = random_amsi_bypass()
        if 'GetProcAddress' in snippet and 'LoadLibrary' in snippet:
            match = re.search(r'public class (\w+)', snippet)
            assert match, 'Class declaration not found'
            cls = match.group(1)
            assert f'[{cls}]::LoadLibrary' in snippet
            assert f'[{cls}]::GetProcAddress' in snippet
            assert f'[{cls}]::VirtualProtect' in snippet
            break
    else:
        pytest.skip('AMSI bypass technique with C# helper class not generated')
