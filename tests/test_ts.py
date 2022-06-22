import math

import pytest

from crypto_app_core import transactions as ts, auth as au


def test_transaction_0(network_create: ts.Network):
    n = network_create

    n.remove_user_by_name('Team')

    assert 'Team' not in map(lambda u: u.name, n.connected_users)


def test_transaction_1a(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')

    assert isinstance(team, ts.HybridUser) and isinstance(kao, ts.HybridUser)

    print(tx_info := ts.GenericTransactionInfo(team, kao, 5), repr(tx_info))

    with pytest.raises(au.AuthenticationError):
        kao.broadcast_transaction(tx_info, kao.private_key)

    print(kao.ledger.transactions, repr(kao.ledger.transactions))
    print(bytes(kao.ledger))


def test_transactions_1b(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')

    assert isinstance(team, ts.HybridUser) and isinstance(kao, ts.HybridUser)

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    with pytest.raises(ts.LedgerAlreadyFull):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )


def test_transactions_1c(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')

    assert isinstance(team, ts.HybridUser) and isinstance(kao, ts.HybridUser)

    for _ in range(n.block_size - 1):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    with pytest.raises(ts.LedgerNotFull):
        kao.create_block()


@pytest.mark.parametrize(('balance', 'out'), ((500, 100), (2000, 50), (70, 7)))
def test_transaction_3(network_create: ts.Network, balance: float, out: float):
    n, bl = network_create, balance

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    _o = out / n.block_size
    _f = n.transaction_fees * n.block_size

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, boss, _o), team.private_key
        )

    boss.update_transaction().create_block()

    assert math.isclose(boss.balance, out + n.block_reward + _f)

    team.cash_in(bl).update_transaction().tally_up().apply()

    assert math.isclose(team.balance, bl - out - _f)


def test_transactions_3a(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    with pytest.raises(ts.LedgerNotFinalized):
        kao.tally_up()


def test_transactions_3b(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    with pytest.raises(ts.LedgerAlreadyTallied):
        kao.update_transaction().tally_up()
        kao.tally_up()


def test_transactions_3c(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    with pytest.raises(ts.LedgerNotTallied):
        kao.update_transaction().apply_tally()


def test_transactions_3d(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    with pytest.raises(ValueError):
        team.update_transaction().tally_up().apply()


def test_transactions_3e(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    with pytest.raises(ts.TallyAlreadyApplied):
        (
            team.update_transaction()
            .cash_in(60)
            .cash_out(9)
            .tally_up()
            .apply()
            .apply_tally()
        )


def test_transactions_3f(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    with pytest.raises(ts.TallyNotApplied):
        team.update_transaction().cash_in(60).tally_up()
        team.finalize_tally()


def test_transactions_3g(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    with pytest.raises(ts.LedgerNotTallied):
        team.update_transaction().cash_in(60)
        team.finalize_tally()


def test_transactions_4(network_create: ts.Network):
    n = network_create

    team = n.get_user_by_name('Team')
    kao = n.get_user_by_name('Kao')
    boss = n.get_user_by_name('Boss')

    assert (
        isinstance(team, ts.HybridUser)
        and isinstance(kao, ts.HybridUser)
        and isinstance(boss, ts.HybridUser)
    )

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(team, kao, 5), team.private_key
        )

    boss.update_transaction().create_block()

    team.update_transaction().cash_in(100).tally_up().apply().finalize_tally()
    kao.update_transaction().tally_up().apply().finalize_tally()

    for _ in range(n.block_size):
        kao.broadcast_transaction(
            ts.GenericTransactionInfo(boss, team, 10), boss.private_key
        )

    team.update_transaction().create_block()

    assert n.block_chain is not None

    print(n.block_chain, repr(n.block_chain), len(n.block_chain))
    for b in n.block_chain:
        print(b, repr(b))

    print(n.block_chain[0], repr(n.block_chain[0]))
