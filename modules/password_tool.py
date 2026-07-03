"""
Module 2: Password Strength Checker + Generator
"""

import re
import math
import secrets
import string


def check_strength(password):
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32

    entropy = length * math.log2(pool_size) if pool_size else 0

    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if has_lower and has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_symbol:
        score += 1

    common_patterns = ["123456", "password", "qwerty", "letmein", "admin", "abc123"]
    is_common = password.lower() in common_patterns

    if is_common:
        rating = "SANGAT LEMAH (password umum/mudah ditebak)"
    elif score <= 2:
        rating = "LEMAH"
    elif score == 3:
        rating = "SEDANG"
    elif score == 4:
        rating = "KUAT"
    else:
        rating = "SANGAT KUAT"

    print(f"\nPanjang       : {length} karakter")
    print(f"Huruf kecil   : {'Ya' if has_lower else 'Tidak'}")
    print(f"Huruf besar   : {'Ya' if has_upper else 'Tidak'}")
    print(f"Angka         : {'Ya' if has_digit else 'Tidak'}")
    print(f"Simbol        : {'Ya' if has_symbol else 'Tidak'}")
    print(f"Estimasi entropy: {entropy:.1f} bits")
    print(f"Rating        : {rating}")

    if length < 12:
        print("Saran: gunakan minimal 12 karakter.")
    if not has_symbol:
        print("Saran: tambahkan simbol seperti ! @ # $ %.")


def generate_password(length=16, use_symbols=True):
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def run():
    print("\n=== PASSWORD STRENGTH CHECKER + GENERATOR ===")
    print("1. Cek kekuatan password")
    print("2. Generate password baru")
    choice = input("Pilih (1/2): ").strip()

    if choice == "1":
        pwd = input("Masukkan password yang mau dicek: ")
        check_strength(pwd)
    elif choice == "2":
        length_input = input("Panjang password [default 16]: ").strip()
        length = int(length_input) if length_input else 16
        pwd = generate_password(length)
        print(f"\nPassword baru: {pwd}")
        check_strength(pwd)
    else:
        print("Pilihan tidak valid.")


if __name__ == "__main__":
    run()
