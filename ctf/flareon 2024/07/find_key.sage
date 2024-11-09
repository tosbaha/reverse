from sage.all import *

def pohlig_hellman(P, Q, bound=None):
    order = P.order()  # Get the order of the point
    factors = factor(order)  # Factor the order
    print(f"Factors: {factors}")
    
    dlogs = []  # To store discrete logs
    primes = []  # To store prime factors
    total_bit_prime = 0  # Track the bit length of primes
    
    for prime, exponent in factors:
        # Calculate subgroup order
        subgroup_order = prime ** exponent
        P_0 = (order // subgroup_order) * P  # Reduce P
        Q_0 = (order // subgroup_order) * Q  # Reduce Q
        
        # Calculate the discrete log in the subgroup
        log = discrete_log(Q_0, P_0, operation='+', algorithm='rho')
        dlogs.append(log)
        primes.append(subgroup_order)

        # Calculate total bit length of primes
        total_bit_prime += subgroup_order.bit_length()
        if bound and total_bit_prime > bound:
            print(f"Total bits exceeded bound: {total_bit_prime} > {bound}")
            break

    # Combine results using CRT
    if dlogs:
        print("Calculating CRT...")
        secret = int(crt(dlogs, primes))
        return secret
    else:
        print("No discrete logs found.")
        return None

def find_private_key(partial_key, step_value, max_iterations, known_public_key, G):
    for n in range(max_iterations):
        candidate_private_key = partial_key + n * step_value
        public_key = candidate_private_key * G        
        if public_key == known_public_key:
            print(f"Found valid private key: {hex(candidate_private_key)}")
            return candidate_private_key

    print("No valid private key found within the iteration limit.")
    return None

p = 0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd
a = 0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
b = 0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380

E = EllipticCurve(GF(p), [a, b])

gx = 0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
gy = 0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182
G = E(gx, gy)

px = 0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499
py = 0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15
P = E(px, py)

partial_key = 3914004671535485983675163411331184
step_value = 4374617177662805965808447230529629 # product of primes that give partial result
max_iterations = 100000

partial_key = pohlig_hellman(G, P, bound=112)
print("Partial Key ", partial_key)

private_key = find_private_key(partial_key, step_value, max_iterations, P, G)
private_key = 0x7ed85751e7131b5eaf5592718bef79a9
recipient_x = 0xb3e5f89f04d49834de312110ae05f0649b3f0bbe2987304fc4ec2f46d6f036f1a897807c4e693e0bb5cd9ac8a8005f06
recipient_y = 0x85944d98396918741316cd0109929cb706af0cca1eaf378219c5286bdc21e979210390573e3047645e1969bdbcb667eb
recipient_public_key = E(recipient_x, recipient_y)
print("Server Public key ", recipient_public_key)
shared_secret_point = private_key * recipient_public_key
print(shared_secret_point)
shared_secret = int(shared_secret_point.xy()[0])
print(hex(shared_secret)) 
