# SPDX-License-Identifier: MIT OR Apache-2.0
# The file maturin would generate; written out because the package also holds
# Python modules. It must import nothing beyond the compiled module.
from .nettls_py import *

__doc__ = nettls_py.__doc__
if hasattr(nettls_py, "__all__"):
    __all__ = nettls_py.__all__
