import random
import time

def tm():
    return time.strftime('%I:%M:%S', time.localtime(time.time()))

RSA = 2200

def number():
    return random.randint(10**(RSA-1), 10**RSA-1)

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

def moduler_(x,d,n):
    count = 1
    r = 1

# a = 2
# b = number()
# c = b - 1
#
# print(moduler(a,b,c))
# print(a**b%c)

# print(tm())
# print(moduler(10^2200,number(),number()))
# print(tm())

print(10**255-1)