#!/usr/bin/env python3
"""
Gerador/validador de PAN pelo algoritmo de Luhn (ISO/IEC 7812-1),
que e' o "script padrao" que todo gateway usa pra validar cartao.

Luhn: da direita pra esquerda, dobra os digitos de posicao par (2o, 4o, ...);
se passar de 9, subtrai 9. Soma tudo. Valido se a soma % 10 == 0.
O ultimo digito (check digit) e' escolhido pra fechar essa conta.

Uso:
  python3 gen_card.py check 5291070000000000
  python3 gen_card.py gen 529107 5        # 5 PANs de 16 digitos no BIN 529107
"""
import random, sys

def luhn_sum(digits):
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s

def is_valid(pan: str) -> bool:
    return luhn_sum([int(c) for c in pan]) % 10 == 0

def check_digit(partial: str) -> int:
    """digito verificador que completa `partial` (sem o ultimo digito)"""
    s = luhn_sum([int(c) for c in partial] + [0])
    return (10 - s % 10) % 10

def gen(bin_prefix: str, length: int = 16, rng=random) -> str:
    body = bin_prefix + "".join(str(rng.randint(0, 9))
                                for _ in range(length - len(bin_prefix) - 1))
    return body + str(check_digit(body))

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "gen"
    if cmd == "check":
        for pan in sys.argv[2:]:
            print(f"{pan}  luhn={'VALIDO' if is_valid(pan) else 'INVALIDO'}"
                  f"  (check digit correto seria {check_digit(pan[:-1])})")
    else:
        bin_prefix = sys.argv[2] if len(sys.argv) > 2 else "529107"
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        for _ in range(n):
            print(gen(bin_prefix))
