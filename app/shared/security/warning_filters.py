"""Third-party deprecation warning filters applied before importing PGPy."""

import warnings

from cryptography.utils import CryptographyDeprecationWarning

# PGPy 0.6.x imports algorithms that cryptography moved to decrepit modules.
# Suppress only PGPy's import-time deprecation warnings; the pinned dependency
# does not emit these warnings during actual PGP operations.
warnings.filterwarnings(
    "ignore",
    category=CryptographyDeprecationWarning,
    module=r"pgpy(\.|$)",
)
