from mpyc.runtime import mpc
from random import randint
import sympy
import time
from gmpy2 import invert, powmod
from sympy import discrete_log


def primitive_element(p, q):
    while True:
        g = randint(2, p - 2)
        if powmod(g, 2, p) != 1 and powmod(g, q, p) != 1:
            return g


def decrypt(c1, c2, p, a):
    v = powmod(c2, a, p)
    v_1 = invert(c1, p)
    m = (v * v_1) % p
    return m


async def zkproof(rank, pk, r, x, e, c, g, h, p):
    m = len(mpc.parties)
    if mpc.pid == rank:
        t1 = randint(1, 10 ** 4)
        t2 = randint(1, 10 ** 4)
        a = None
    elif mpc.pid == (rank + 1) % m:
        a = randint(1, 10 ** 4)
        t1 = None
        t2 = None
    else:
        a = None
        t1 = None
        t2 = None
    t1 = await mpc.transfer(t1, senders=rank)
    t2 = await mpc.transfer(t2, senders=rank)
    t_1 = powmod(pk, t1, p)
    t_2 = powmod(g, t2, p) * powmod(h, t1, p) % p
    a = await mpc.transfer(a, senders=(rank + 1) % m)
    if mpc.pid == rank:
        s1 = (t1 + a * r) % (p - 1)
        s2 = (t2 + a * x) % (p - 1)
    else:
        s1 = None
        s2 = None
    s1 = await mpc.transfer(s1, senders=rank)
    s2 = await mpc.transfer(s2, senders=rank)
    if (t_1 * powmod(e, a, p)) % p == powmod(pk, s1, p):
        if (t_2 * powmod(c, a, p)) % p == powmod(g, s2, p) * powmod(h, s1, p) % p:
            print("zero knowledge proof passed!")
            return 1
        else:
            print("zero knowledge proof failed!")
            return 0
    else:
        print("zero knowledge proof failed!")
    del t1, t2, a, t_1, t_2, s1, s2
    return 0


def verify(x, r, c, g, h, p):
    if c == powmod(g, x, p) * powmod(h, r, p) % p:
        print("verified")
        return 1
    else:
        print("verify failed")
        return 0


async def main():
    if mpc.pid == 0:
        while True:
            q = sympy.randprime(2 ** 31, 2 ** 32 - 1)
            if sympy.isprime(q):
                p = 2 * q + 1
                if sympy.isprime(p):
                    break
        # Generate a generator h and a random value g
        g = primitive_element(p, q)
        h = randint(1, q - 2)
        sk0 = randint(1, p - 1)
        C = p, q, g, h, sk0
    else:
        C = None
    m = len(mpc.parties)
    # rank = mpc.pid
    await mpc.start()
    # Shared parameter value
    C = await mpc.transfer(C, senders=0)
    p, q, g, h, sk0 = C

    pk0 = powmod(h, sk0, p)
    # Generate a private key and a public key, and hold the public key together
    sk = randint(1, p - 1)
    pk = powmod(h, sk, p)
    for i in range(m):
        pk1 = await mpc.transfer(pk, senders=i)
        pk0 = pk0 * pk1 % p
        del pk1
    pk = pk0
    # Generated random share
    x = randint(1, q - 1)
    r = randint(1, q - 1)
    # Calculated commitment values
    time0 = time.time()
    c = powmod(g, x, p) * powmod(h, r, p) % p
    e = powmod(pk, r, p)
    time1 = time.time()
    print("The time to calculate the commitment values:", (time1 - time0) * 1000, "ms")
    co = []
    en = []
    for i in range(m):
        c1 = await mpc.transfer(c, senders=i)
        e1 = await mpc.transfer(e, senders=i)
        co.append(c1)
        en.append(e1)
        del c1, e1
    # zero knowledge proof
    for i in range(m):
        await zkproof(i, pk, r, x, en[i], co[i], g, h, p)

    # Verify the share and random value
    if mpc.pid < 2:  # Send wrong shares
        x = x + 1

    data = x, r
    data_x = []
    data_r = []
    for i in range(m):
        data_1 = await mpc.transfer(data, senders=i)
        x1, r1 = data_1
        data_x.append(x1)
        data_r.append(r1)
        del x1, r1, data_1
    resul = []
    for i in range(m):
        a = verify(data_x[i], data_r[i], co[i], g, h, p)
        resul.append(a)
    print("Data sent by all parties:", data_x)
    time2 = time.time()
    if sum(resul) < m:
        sk_val = []
        for i in range(m):
            sk1 = await mpc.transfer(sk, senders=i)
            sk_val.append(sk1)
            del sk1
        sk_data = (sk0 + sum(sk_val)) % q
        # decrypt
        sk_ = invert(sk_data, q)
        print("sk^-1", sk_)
    reconstruct = []
    for i in range(m):
        if resul[i] == 1:
            reconstruct.append(data_x[i])
        else:
            mi = decrypt(en[i], co[i], p, sk_data)
            x_2 = discrete_log(p, mi, g)
            x_real = x_2 * sk_ % q
            reconstruct.append(x_real)
    time3 = time.time()
    print("rec time:", time3 - time2, "s")
    print("Get the true share:", reconstruct)
    print("secret reconstructed:", sum(reconstruct) % q)
    await mpc.shutdown()


if __name__ == '__main__':
    mpc.run(main())