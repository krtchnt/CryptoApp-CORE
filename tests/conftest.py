import pytest

from crypto_app_core import transactions as ts


@pytest.fixture
def network_create():
    with ts.Network.temporary(difficulity=16**62) as N:
        team = ts.HybridUser("Team")
        kao = ts.HybridUser("Kao")
        boss = ts.HybridUser("Boss")

        N.connected_users.append(team)
        N.connected_users.append(kao)
        N.connected_users.append(boss)

        yield N
