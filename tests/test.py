def main():
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    from crypto_app_core import transactions as ts


    N = ts.Network()

    team = ts.HybridUser("Team")
    kao = ts.HybridUser("Kao")
    boss = ts.HybridUser("Boss")
    
    N.connected_users.append(team)
    N.connected_users.append(kao)
    N.connected_users.append(boss)

    assert isinstance(team.private_key, rsa.RSAPrivateKey)
    for _ in range(10):
        kao.broadcast_transaction(ts.TransactionInfo(team, boss, 10), team.private_key)

    boss.update_transaction().create_block()

    print(boss.balance)

    team.cash_in(200).update_transaction().tally_up().apply()

    print(team.balance)

    print(repr(N.block_chain))


if __name__ == '__main__':
    main()
