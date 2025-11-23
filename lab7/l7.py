def mod_inverse(a: int, m: int):
    if a < 0:
        a = (a % m + m) % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception("Обратного элемента не существует")
    return x % m


def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def point_add(x1: int, y1: int, x2: int, y2: int, a: int, p: int):
    if x1 == x2 and y1 == y2:
        lambda_val = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
    else:
        lambda_val = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p

    x3 = (lambda_val * lambda_val - x1 - x2) % p
    y3 = (lambda_val * (x1 - x3) - y1) % p
    return x3, y3


def point_multiply(k: int, x: int, y: int, a: int, p: int):
    result_x, result_y = None, None
    buf_x, buf_y = x, y
    
    while k:
        if k & 1: 
            if result_x is None:
                result_x, result_y = buf_x, buf_y
            else:
                result_x, result_y = point_add(result_x, result_y, buf_x, buf_y, a, p)
        
        buf_x, buf_y = point_add(buf_x, buf_y, buf_x, buf_y, a, p)
        k >>= 1
    
    return result_x, result_y


# https://intuit.ru/studies/courses/552/408/lecture/9373?page=6
if __name__ == "__main__":
    a = 2
    b = 3
    p = 67
    ex1, ey1 = 2, 22
    d = 4
    ex2, ey2 = point_multiply(d, ex1, ey1, a, p)
    
    msg = (24, 26)
    r = 2
    print(f"Исходное сообщение: {msg}")

    c1 = point_multiply(r, ex1, ey1, a, p)
    re2 = point_multiply(r, ex2, ey2, a, p)
    c2 = point_add(re2[0], re2[1], msg[0], msg[1], a, p)
    print(f"Шифротекст: ({c1}, {c2})")
    
    
    d_c1 = point_multiply(d, c1[0], c1[1], a, p)
    msg_res = point_add(c2[0], c2[1], d_c1[0], (-d_c1[1])%p, a, p)
    print(f"Расшифрованное сообщение: {msg_res}")

    print(f"Совпадают ли сообщения: {msg_res == msg}")
