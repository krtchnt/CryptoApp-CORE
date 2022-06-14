def main():
    from crypto_app_core import transactions as tx

    team = tx.HybridUser("Team")
    kao = tx.HybridUser("Kao")
    boss = tx.HybridUser("Boss")

    for _ in range(10):
        kao.broadcast_transaction(tx.TransactionInfo(team, boss, 10), team.private_key)

    boss.update_transaction().create_block()

    print(boss.balance)

    team.cash_in(200).update_transaction().tally_up().apply_tally()

    print(team.balance)

    print(repr(tx.N.block_chain))


if __name__ == '__main__':
    main()
