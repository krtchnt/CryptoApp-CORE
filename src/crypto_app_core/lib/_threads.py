import concurrent.futures as conc_futr


I = 100_000_000


def f(x: int):
    i = 0
    while True:
        if x - i <= 1:
            return i
        i += 1


def thread_1(x: int):
    i = 0
    while True:
        if x - i <= 1:
            return i
        i += 2


def thread_2(x: int):
    i = 1
    while True:
        if x - i <= 1:
            return i
        i += 2


with conc_futr.ThreadPoolExecutor() as executor:
    future_1 = executor.submit(thread_1, I)
    future_2 = executor.submit(thread_2, I)

    result = conc_futr.wait((future_1, future_2), return_when=conc_futr.FIRST_COMPLETED)
    print(result.done)


print(f(I))
