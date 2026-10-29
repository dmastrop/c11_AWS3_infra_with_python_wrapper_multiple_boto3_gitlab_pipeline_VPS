#!/usr/bin/env python3

def classify_number(n):
    if n < 0:
        return "negative"
    elif n == 0:
        return "zero"
    else:
        return "positive"


for value in [-5, 0, 7]:
    result = classify_number(value)
    print(f"{value}: {result}")
