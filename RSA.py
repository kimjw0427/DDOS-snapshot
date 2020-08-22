import random
import time
import decimal

def tm():
    return time.strftime('%I:%M:%S', time.localtime(time.time()))

RSA = 617

def number():
    return random.randint(10**(RSA-1), 10**RSA-2)

def moduler(x,d,n):
    nn = str(format(d, 'b'))
    y = x%n
    m = 1
    r = 1
    while(m <= len(nn)):
        if (nn[len(nn) - m] == '1'):
            r = r * y % n
        y = y**2 % n
        m = m + 1
    return r

def prime(a):
    if a%2 == 0:
        a = a + 1
    while not ((moduler(2,a-1,a) == 1) and not ((a-1)%3 == 0)):
        if a <= (10**256)/2:
            a = a + 2
        if a >= (10**256)/2:
            a = a - 2
    return a


def exeu(a, b):
    c = 1
    while not ((b*c+1)%a == 0):
        c = c + 1
    return int((b*c+1)/a)
# def exeu(a, b):
#     x0, x1, y0, y1 = 1, 0, 0, 1
#
#     while b != 0:
#         n, a, b = a // b, b, a % b
#         x0, x1 = x1, x0 - n * x1
#         y0, y1 = y1, y0 - n * y1
#
#     return x0, y0

p = number()
# q = number()

print(tm())
print(moduler(2, p, p-1))
print(tm())

print(format(10**255, 'b'))

# print('소수 구하는 중')
#
# p = prime(p)
# q = prime(q)
#
# print(p)
# print(q)
#
# e = 3
#
# print('d를 구하는 중')
#
# d = exeu(e,(p-1)*(q-1))
# print(d)
#
# if not e*d % ((p-1)*(q-1)) == 1:
#     print('실패')
# print('복호화 키: ', d)
#
# N = p*q
#
# print('공개키1: ', N)
# print('공개키2: ', e)
#
# a = 10427
#
# print('암호: ', a)
#
# x = moduler(a,e,N)
#
# print('암호화: ', x)
#
# aa = moduler(x,d,N)
#
# print('복호화: ', aa)