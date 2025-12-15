# Generator numeru PESEL
# PESEL składa się z 11 cyfr: RRMMDDPPPPK
# RR - rok urodzenia (ostatnie 2 cyfry)
# MM - miesiąc urodzenia (z modyfikacją dla różnych stuleci)
# DD - dzień urodzenia
# PPPP - numer porządkowy (ostatnia cyfra określa płeć: parzysta=kobieta, nieparzysta=mężczyzna)
# K - cyfra kontrolna

import random
from datetime import datetime


def calculate_control_digit(pesel_10_digits):
    """Oblicza cyfrę kontrolną dla pierwszych 10 cyfr PESEL"""
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    sum_weighted = sum(
        int(digit) * weight for digit, weight in zip(pesel_10_digits, weights)
    )
    control_digit = (10 - (sum_weighted % 10)) % 10
    return str(control_digit)


def get_month_with_century_modifier(year, month):
    """Zwraca miesiąc z modyfikatorem stulecia zgodnie z algorytmem PESEL"""
    if 1900 <= year <= 1999:
        return month  # Bez modyfikacji
    elif 2000 <= year <= 2099:
        return month + 20  # Dodaj 20
    elif 2100 <= year <= 2199:
        return month + 40  # Dodaj 40
    elif 2200 <= year <= 2299:
        return month + 60  # Dodaj 60
    elif 1800 <= year <= 1899:
        return month + 80  # Dodaj 80
    else:
        raise ValueError(f"Rok {year} nie jest obsługiwany przez algorytm PESEL")


def generate_pesel(birth_date, gender):
    """
    Generuje prawidłowy numer PESEL

    Args:
        birth_date (str): Data urodzenia w formacie DD.MM.RRRR
        gender (str): Płeć - 'Mężczyzna' lub 'Kobieta'

    Returns:
        str: 11-cyfrowy numer PESEL
    """
    # Parsowanie daty urodzenia
    day, month, year = map(int, birth_date.split("."))

    # Specjalna walidacja dla 29 lutego 1900 (rok nieprzestępny dla PESEL)
    if day == 29 and month == 2 and year == 1900:
        raise ValueError(
            "Błąd w generowaniu PESEL: 29 lutego 1900 nie jest prawidłową datą dla PESEL."
        )

    # Walidacja daty
    try:
        datetime(year, month, day)
    except ValueError as e:
        raise ValueError(f"Nieprawidłowa data: {birth_date} - {e}") from e

    # Formatowanie roku (ostatnie 2 cyfry)
    year_2_digits = year % 100

    # Miesiąc z modyfikatorem stulecia
    month_with_modifier = get_month_with_century_modifier(year, month)

    # Generowanie numeru porządkowego (3 cyfry + cyfra płci)
    # Ostatnia cyfra: parzysta dla kobiet, nieparzysta dla mężczyzn
    serial_number = random.randint(100, 999)

    if gender.lower() in ["mężczyzna", "m", "male"]:
        gender_digit = random.choice([1, 3, 5, 7, 9])
    elif gender.lower() in ["kobieta", "k", "female", "f"]:
        gender_digit = random.choice([0, 2, 4, 6, 8])
    else:
        raise ValueError(f"Nieprawidłowa wartość płci: {gender}")

    # Składanie pierwszych 10 cyfr
    pesel_10 = f"{year_2_digits:02d}{month_with_modifier:02d}{day:02d}{serial_number}{gender_digit}"

    # Obliczanie cyfry kontrolnej
    control_digit = calculate_control_digit(pesel_10)

    # Pełny PESEL
    pesel = pesel_10 + control_digit

    return pesel


def validate_pesel(pesel):
    """
    Waliduje numer PESEL

    Args:
        pesel (str): Numer PESEL do walidacji

    Returns:
        bool: True jeśli PESEL jest prawidłowy
    """
    if len(pesel) != 11 or not pesel.isdigit():
        return False

    # Sprawdzenie cyfry kontrolnej
    calculated_control = calculate_control_digit(pesel[:10])
    return calculated_control == pesel[10]


def extract_info_from_pesel(pesel):
    """
    Wyciąga informacje z numeru PESEL

    Args:
        pesel (str): Numer PESEL

    Returns:
        dict: Słownik z informacjami (data urodzenia, płeć)
    """
    if not validate_pesel(pesel):
        return None

    year_2 = int(pesel[0:2])
    month_mod = int(pesel[2:4])
    day = int(pesel[4:6])
    gender_digit = int(pesel[9])

    # Określenie stulecia i miesiąca
    if 1 <= month_mod <= 12:
        year = 1900 + year_2
        month = month_mod
    elif 21 <= month_mod <= 32:
        year = 2000 + year_2
        month = month_mod - 20
    elif 41 <= month_mod <= 52:
        year = 2100 + year_2
        month = month_mod - 40
    elif 61 <= month_mod <= 72:
        year = 2200 + year_2
        month = month_mod - 60
    elif 81 <= month_mod <= 92:
        year = 1800 + year_2
        month = month_mod - 80
    else:
        return None

    # Określenie płci
    gender = "Kobieta" if gender_digit % 2 == 0 else "Mężczyzna"

    return {
        "birth_date": f"{day:02d}.{month:02d}.{year}",
        "gender": gender,
        "year": year,
        "month": month,
        "day": day,
    }


# Funkcja testowa
if __name__ == "__main__":
    # Test generowania PESEL
    test_date = "15.03.1985"
    test_gender = "Mężczyzna"

    pesel = generate_pesel(test_date, test_gender)
    print(f"Wygenerowany PESEL: {pesel}")
    print(f"Walidacja: {validate_pesel(pesel)}")

    info = extract_info_from_pesel(pesel)
    print(f"Informacje z PESEL: {info}")
