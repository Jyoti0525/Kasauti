import os

import pytest

from kasauti.semantic.embed import Embedder, shared


@pytest.fixture(scope="session")
def embedder() -> Embedder:
    """The installed model. CI fetches it and sets KASAUTI_REQUIRE_MODEL, so there a missing
    model fails these tests instead of skipping them."""
    loaded = shared()
    if loaded is None:
        if os.environ.get("KASAUTI_REQUIRE_MODEL"):
            pytest.fail("the embedding model isn't installed: run `kasauti models fetch`")
        pytest.skip("the embedding model isn't installed (`kasauti models fetch`)")
    return loaded
