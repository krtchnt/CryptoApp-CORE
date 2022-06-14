import abc
import enum as e
import time
import base64 as b64
import typing as t
import logging
import itertools

import attr as a
import coloredlogs
import pymerkle as mk
import cryptography.exceptions as crypto_exc

from cryptography.hazmat.primitives import hashes as hsh
from cryptography.hazmat.primitives.asymmetric import padding as pdd, rsa

from . import auth
from .lib import utils


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG, logger=logger)

sign_padding = pdd.PSS(mgf=pdd.MGF1(auth.hash_algo), salt_length=pdd.PSS.MAX_LENGTH)


class BaseTransactionException(Exception, metaclass=abc.ABCMeta):
    pass


class LedgerException(BaseTransactionException, metaclass=abc.ABCMeta):
    pass


class LedgerOverflow(LedgerException):
    pass


class LedgerNotFull(LedgerException):
    pass


class LedgerNotTallied(LedgerException):
    pass


class LedgerNotFinalized(LedgerException):
    pass


class TallyAlreadyApplied(LedgerException):
    pass


@a.define
class Network(metaclass=utils.Singleton):
    block_chain: 't.Optional[BlockChain]' = None
    transactions: 'list[list[Transaction]]' = a.field(factory=lambda: [[]])
    current_block_index: int = a.field(default=0, init=False)
    connected_users: 'set[ExpensingUser]' = a.field(factory=set, init=False)

    block_reward: float = a.field(kw_only=True, default=5.000_000)
    difficulity: int = a.field(
        kw_only=True,
        default=0x00100000_00000000_00000000_00000000_00000000_00000000_00000000_00000000,
    )
    transaction_fees: float = a.field(kw_only=True, default=0.010_000)

    @property
    def current_transactions(self):
        return self.transactions[self.current_block_index]

    def increment_block_index(self):
        self.current_block_index += 1

    def get_user_with_name(self, name: str):
        return next((u for u in self.connected_users if u.name == name), None)


N = Network()


@a.frozen(frozen=True, eq=True, order=True, hash=True)
class TransactionInfo:
    sender: 'ExpensingUser | NetworkTransactionManager'
    recipient: 'ExpensingUser'
    amount: float
    fee: float = a.field(kw_only=True, default=N.transaction_fees)
    message: t.Optional[str] = a.field(kw_only=True, default=None)

    def __repr__(self):
        return '<TransactionInfo {0.sender} ==> {0.recipient} amount={0.amount} (fee={0.fee}) | message="{0.message}">'.format(
            self
        )

    def __str__(self):
        return '%s@%i' % (__class__.__name__, id(self))


class TransactionType(e.Enum):
    GENERIC = e.auto()
    FEES_PAIDOUT = e.auto()
    BLOCK_REWARD = e.auto()


@a.frozen(frozen=True, eq=True, order=True, hash=True)
class Transaction:
    index: int
    submitter: 'User'
    info: TransactionInfo
    signature: str
    type: TransactionType = a.field(default=TransactionType.GENERIC, kw_only=True)

    def __repr__(self):
        return '<Transaction #{0.index} submitter={0.submitter} info={0.info} | \n     signature={0.signature}>'.format(
            self
        )

    def __str__(self):
        return '%s@%i' % (__class__.__name__, id(self))

    def __bytes__(self):
        return self.__repr__().encode('utf-8')


@a.define(eq=True, order=True, hash=True)
class Transactions(list[Transaction]):
    capacity: int = a.field(default=10, init=False, repr=False)

    @property
    def generic(self):
        return (*(tx for tx in self if tx.type is TransactionType.GENERIC),)

    @property
    def fees_paidout(self):
        if (tx := self[-2]).type is TransactionType.FEES_PAIDOUT:
            return tx

    @property
    def block_reward(self):
        if (tx := self[-1]).type is TransactionType.BLOCK_REWARD:
            return tx

    @property
    def root_hash(self) -> bytes:
        tree = mk.MerkleTree('sha3_256')
        for tx in self:
            tree.encrypt(bytes(tx))  # pyright: reportUnknownMemberType=false
        h: bytes = tree.get_root_hash()
        return h

    def append(self, transaction: Transaction, /):
        """Append a new transaction

        Args:
            transaction (`Transaction`): The transaction to be appended

        Raises:
            `LedgerOverflow`: If the ledger is already full
        """

        if (
            len(self.generic) >= self.capacity
            and self.block_reward
            and self.fees_paidout
        ):
            logger.warning(
                "Failed to append another transaction because ledger is already full"
            )
            raise LedgerOverflow("Ledger is already full")
        super().append(transaction)
        logger.debug('Appended %s to %s' % (transaction, self))

    def __repr__(self):
        return '[Transactions: \n%s\n ]' % '\n'.join(
            ('    %s,' % repr(t) for t in self)
        )

    def __str__(self):
        return '%s@%i' % (__class__.__name__, id(self))


@a.define(eq=True, order=True, hash=True)
class Ledger:
    transactions: Transactions
    tally: 't.Optional[Tally]' = a.field(default=None, init=False)
    tallied: bool = a.field(factory=bool, init=False)

    def __bytes__(self) -> bytes:
        return self.__repr__().encode('utf-8')

    def index_transaction_info(self, info: TransactionInfo, /):
        return f"{len(self.transactions)}#{info!r}".encode('utf-8')

    def tally_up(self) -> 'Tally':
        if self.tallied:
            raise LedgerNotTallied("Ledger is already tallied")
        txs = self.transactions
        if len(txs.generic) < txs.capacity:
            raise LedgerNotFull("Ledger is not yet full")
        if not (txs.block_reward and txs.fees_paidout):
            raise LedgerNotFinalized("Ledger is not yet finalized")
        r_d = utils.freeze_dict(
            {
                id(r_u): sum(map(lambda tx: tx.info.amount, txs_))
                for r_u, txs_ in utils.groupby(
                    self.transactions, key=lambda tx: tx.info.recipient
                ).items()
            }
        )

        s_d = utils.freeze_dict(
            {
                id(s_u): sum(map(lambda tx: -tx.info.amount, txs_))
                for s_u, txs_ in utils.groupby(
                    self.transactions.generic,
                    key=lambda tx: tx.info.sender,
                ).items()
            }
        )

        self.tallied = True
        self.tally = (tally := Tally(r_d, s_d))
        return tally


PartialTallyPairs: t.TypeAlias = 'utils.FrozenDict[int, float]'
"""A type alias for a dict type for a ledger tally"""


@a.define(eq=True, order=True, hash=True)
class Tally:
    earnings: PartialTallyPairs = a.field(on_setattr=a.setters.frozen)
    expenses: PartialTallyPairs = a.field(on_setattr=a.setters.frozen)
    applied: bool = a.field(factory=bool, init=False)

    @property
    def net_tally(self):
        return utils.dict_merge(self.expenses, self.earnings, lambda x, y: x + y)

    def apply(self, user: 'ExpensingUser'):
        if self.applied:
            raise TallyAlreadyApplied('This tally has already been applied')
        user.balance += self.net_tally[id(user)]
        self.applied = True


@a.define(eq=True)
class User(metaclass=abc.ABCMeta):
    name: str
    private_key: rsa.RSAPrivateKey = a.field(
        factory=lambda: rsa.generate_private_key(65537, key_size=2048),
        init=False,
        repr=False,
    )


class NetworkTransactionManager(User, metaclass=utils.Singleton):
    def __init__(self):
        return super().__init__(name='Rewarder')

    def __repr__(self):
        return 'Rewarder'


MANAGER = NetworkTransactionManager()


@a.define(init=False, eq=True, order=True)
class ExpensingUser(User, metaclass=abc.ABCMeta):
    ledger: Ledger = a.field(
        factory=lambda: Ledger(Transactions()), init=False, repr=False
    )
    balance: float = a.field(
        default=0.0,
        kw_only=True,
        validator=a.validators.ge(0),
        on_setattr=a.setters.validate,
    )
    caught_up_block_index: int = a.field(default=0, init=False)

    def __attrs_post_init__(self):
        N.connected_users.add(self)

    def cash_in(self, amount: float, /):
        self.balance += amount
        return self

    def cash_out(self, amount: float, /):
        self.balance -= amount
        return self

    def tally_up(self):
        self.ledger.tally_up()
        return self

    def apply_tally(self):
        if not (tally := self.ledger.tally):
            raise LedgerNotTallied("Ledger is not yet tallied")
        tally.apply(self)
        return self

    def increment_block_index(self):
        self.caught_up_block_index += 1
        return self

    def increment_block_index_reset_transactions(self):
        if not self.ledger.tallied:
            raise LedgerNotTallied("Ledger is not yet tallied")
        self.ledger.transactions.clear()
        return self.increment_block_index()

    @property
    def caught_up_transactions(self):
        return N.transactions[self.caught_up_block_index]


class ActualUserMixin(ExpensingUser, metaclass=abc.ABCMeta):
    def __str__(self):
        return '%s@%i' % (self.name, id(self))

    def broadcast_transaction(
        self, tx_info: TransactionInfo, /, private_key: rsa.RSAPrivateKey
    ):
        i = len(self.ledger.transactions)
        data = self.ledger.index_transaction_info(tx_info)
        err_args = (self, tx_info.sender, tx_info)

        try:
            signature = private_key.sign(data, sign_padding, auth.hash_algo)
        except Exception:
            logger.critical(
                '%s failed to sign %s\'s transaction info %s\n:: Unhandled exception occured.'
                % err_args
            )
            raise
        logger.debug('%s signed transaction info %s' % (self, tx_info))

        try:
            tx_info.sender.private_key.public_key().verify(
                signature, data, sign_padding, auth.hash_algo
            )
        except crypto_exc.InvalidSignature as exc:
            logger.error(
                "%s failed to verify %s\'s transaction info %s\n:: Signature does not match."
                % err_args
            )
            raise auth.AuthenticationError(
                "%s failed to verify %s\'s transaction info %s: Signature does not match."
                % err_args
            ) from exc
        except Exception:
            logger.critical(
                '%s failed to verify %s\'s transaction info %s\n:: Unhandled exception occured.'
                % err_args
            )
            raise

        tx = Transaction(
            index=i,
            submitter=self,
            info=tx_info,
            signature=b64.b64encode(signature).decode('ascii'),
        )
        logger.debug('%s successfully verfied transaction info %s' % (self, tx_info))

        self.ledger.transactions.append(tx)
        N.current_transactions.append(tx)
        logger.info('%s submitted %s to the pool' % (self, tx))
        return tx

    def update_transaction(self):
        caught_up_network_txs, own_txs = (
            self.caught_up_transactions,
            self.ledger.transactions,
        )
        if own_txs != caught_up_network_txs:
            own_txs.clear()
            own_txs.extend(caught_up_network_txs)
            # for tx in N.transactions_history:
            #     if tx not in self.ledger.transactions:
            #         logger.debug('%s appended %s their personal ledger' % (self, tx))
            #         self.ledger.transactions.append(tx)
            logger.info('%s updated their personal ledger' % self)
        return self


class MinerMixin(ExpensingUser, metaclass=abc.ABCMeta):
    def mine(self) -> int:
        if len(self.ledger.transactions) < self.ledger.transactions.capacity:
            logger.warning(
                '%s failed to start mining because their personal ledger is not yet completed'
                % self
            )
            raise LedgerNotFull("Ledger is not yet full")
        logger.info('%s started mining' % self)
        for proof_of_work in itertools.count():
            _h = hsh.Hash(auth.hash_algo)
            _h.update(self.ledger.transactions.root_hash)
            _h.update(proof_of_work.to_bytes(8, 'big', signed=False))
            h = int(_h.finalize().hex(), base=16)

            if h < N.difficulity:
                logger.info(
                    '%s successfully mined with proof of work %i'
                    % (self, proof_of_work)
                )
                return proof_of_work
        raise RuntimeError

    def create_block(self, *, proof_of_work: t.Optional[int] = None):
        if proof_of_work is None:
            proof_of_work = self.mine()

        if N.block_chain is None:
            N.block_chain = BlockChain()
        logger.info(
            '%s started creating a block in the block chain %s' % (self, N.block_chain)
        )

        total_fees = sum(tx.info.fee for tx in self.ledger.transactions)
        total_bonus = total_fees + N.block_reward

        fees_tx_info = TransactionInfo(
            MANAGER, self, total_fees, fee=0, message='Transaction Fees Paidout'
        )
        fees_tx_data = self.ledger.index_transaction_info(fees_tx_info)
        fees_tx_i = self.ledger.transactions.capacity
        fees_tx_sig = b64.b64encode(
            MANAGER.private_key.sign(fees_tx_data, sign_padding, auth.hash_algo)
        ).decode('ascii')
        fees_tx = Transaction(
            fees_tx_i,
            MANAGER,
            fees_tx_info,
            fees_tx_sig,
            type=TransactionType.FEES_PAIDOUT,
        )

        rwd_tx_info = TransactionInfo(
            MANAGER, self, N.block_reward, fee=0, message='Block Reward'
        )
        rwd_tx_data = self.ledger.index_transaction_info(rwd_tx_info)
        rwd_tx_i = self.ledger.transactions.capacity + 1
        rwd_tx_sig = b64.b64encode(
            MANAGER.private_key.sign(rwd_tx_data, sign_padding, auth.hash_algo)
        ).decode('ascii')
        rwd_tx = Transaction(
            rwd_tx_i,
            MANAGER,
            rwd_tx_info,
            rwd_tx_sig,
            type=TransactionType.BLOCK_REWARD,
        )

        self.ledger.transactions.append(fees_tx)
        self.ledger.transactions.append(rwd_tx)

        N.current_transactions.extend((fees_tx, rwd_tx))
        logger.debug(
            '%s recieved ◈%f worth of transaction fees and ◈%f as block reward (◈%f in total) an added a transaction to their personal ledger'
            % (self, total_fees, N.block_reward, total_bonus)
        )

        tx_root = self.ledger.transactions.root_hash.decode('ascii')
        block_data = BlockData(tx_root, proof_of_work, time.time_ns() / 1_000_000_000)
        block = N.block_chain.append(block_data)
        N.increment_block_index()

        self.tally_up().apply_tally().increment_block_index_reset_transactions()
        logger.info(
            '%s successfully created a block and appended it to the block chain %s'
            % (self, N.block_chain)
        )
        return block


@a.define(eq=True, order=True, hash=True)
class HybridUser(ActualUserMixin, MinerMixin):
    pass


@a.define(eq=True, order=True, hash=True)
class PureUser(ActualUserMixin):
    pass


@a.define(eq=True, order=True, hash=True)
class PureMiner(MinerMixin):
    pass


@a.define(eq=True, order=True)
class BlockData:
    transactions_root_hash: str
    nonce: int
    timestamp: float


@a.define(eq=True, order=True)
class Block:
    data: BlockData
    next: 't.Optional[Block]' = a.field(
        default=None,
        init=False,
        repr=False,
    )
    prev: 't.Optional[Block]' = a.field(
        default=None,
        init=False,
        repr=False,
    )
    prev_block_hash: t.Optional[str] = None

    def __str__(self):
        return '%s@%i' % (__class__.__name__, id(self))

    def __bytes__(self):
        return self.__repr__().encode('utf-8')


@a.define(eq=True, order=True)
class BlockChain:
    head: t.Optional[Block] = None

    def __iter__(self):
        block = self.head
        while block is not None:
            yield block
            block = block.next

    def __repr__(self):
        block = self.head
        blocks: list[Block] = []
        while block is not None:
            blocks.append(block)
            block = block.next
        return '\n  |\n  |\n'.join(map(repr, blocks))

    def __str__(self):
        return '%s@%i' % (__class__.__name__, id(self))

    def __len__(self):
        l = 0
        for _ in self:
            l += 1
        return l

    def push(self, new_data: BlockData, /):
        new_block = Block(new_data)
        new_block.next = self.head
        if self.head is not None:
            self.head.prev = new_block
        self.head = new_block

    def append(self, new_data: BlockData, /):
        new_block = Block(new_data)
        new_block.next = None
        if self.head is None:
            new_block.prev = None
            self.head = new_block
            return new_block
        last = self.head
        while last.next is not None:
            last = last.next
        last.next = new_block
        new_block.prev = last

        h = hsh.Hash(auth.hash_algo)
        h.update(bytes(new_block.prev))
        new_block.prev_block_hash = h.finalize().hex()
        return new_block
