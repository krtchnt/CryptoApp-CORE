import abc
import typing as t
import functools as ft
import collections as cl


class Singleton(abc.ABCMeta, type):
    _instances: 'dict[type, Singleton]' = {}

    def __call__(cls, *args: t.Any, **kwargs: t.Any):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


__E = t.TypeVar('__E')
_KE = t.TypeVar('_KE')

FrozenDict = tuple[tuple[_KE, __E], ...]


def groupby(
    seq: t.Iterable[__E], /, *, key: t.Callable[[__E], _KE] = lambda e: e
) -> dict[_KE, list[__E]]:
    d: dict[_KE, list[__E]] = cl.defaultdict(list)
    return ft.reduce(lambda grp, val: grp[key(val)].append(val) or grp, seq, d)


def freeze_dict(d: dict[__E, _KE]) -> FrozenDict[__E, _KE]:
    return (*zip(d.keys(), d.values()),)


def dict_merge(
    d1: dict[_KE, __E] | FrozenDict[_KE, __E],
    d2: dict[_KE, __E] | FrozenDict[_KE, __E],
    merge_fn: t.Callable[[__E, __E], __E] = lambda x, y: y,
):
    """
    Merges two dictionaries, non-destructively, combining
    values on duplicate keys as defined by the optional merge
    function.  The default behavior replaces the values in d1
    with corresponding values in d2.  (There is no other generally
    applicable merge strategy, but often you'll have homogeneous
    types in your dicts, so specifying a merge technique can be
    valuable.)

    Examples:

    >>> d1
    {'a': 1, 'c': 3, 'b': 2}
    >>> merge(d1, d1)
    {'a': 1, 'c': 3, 'b': 2}
    >>> merge(d1, d1, lambda x,y: x+y)
    {'a': 2, 'c': 6, 'b': 4}

    """
    result = dict(d1)
    for k, v in dict(d2).items():
        if k in result:
            result[k] = merge_fn(result[k], v)
        else:
            result[k] = v
    return result
