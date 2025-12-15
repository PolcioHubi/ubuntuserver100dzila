import pytest
from pesel_generator import (
    calculate_control_digit,
    get_month_with_century_modifier,
    generate_pesel,
    validate_pesel,
    extract_info_from_pesel,
)


def test_get_month_with_century_modifier_unsupported_year():
    """
    Testuje, czy get_month_with_century_modifier rzuca ValueError dla nieobsługiwanych lat.
    """
    with pytest.raises(ValueError, match="Rok 1799 nie jest obsługiwany przez algorytm PESEL"):
        get_month_with_century_modifier(1799, 1)
    with pytest.raises(ValueError, match="Rok 2300 nie jest obsługiwany przez algorytm PESEL"):
        get_month_with_century_modifier(2300, 1)


def test_generate_pesel_invalid_date_1900():
    """
    Testuje, czy generate_pesel rzuca ValueError dla 29 lutego 1900.
    """
    with pytest.raises(ValueError, match="Błąd w generowaniu PESEL: 29 lutego 1900 nie jest prawidłową datą dla PESEL."):
        generate_pesel("29.02.1900", "Mężczyzna")


def test_generate_pesel_invalid_date_format():
    """
    Testuje, czy generate_pesel rzuca ValueError dla nieprawidłowego formatu daty.
    """
    with pytest.raises(ValueError, match="Nieprawidłowa data: 32.01.2020 - day is out of range for month"):
        generate_pesel("32.01.2020", "Mężczyzna")
    with pytest.raises(ValueError, match="Nieprawidłowa data: 01.13.2020 - month must be in 1..12"):
        generate_pesel("01.13.2020", "Mężczyzna")


def test_extract_info_from_pesel_invalid_month_modifier():
    """
    Testuje, czy extract_info_from_pesel zwraca None dla nieprawidłowego modyfikatora miesiąca.
    """
    # PESEL z nieprawidłowym modyfikatorem miesiąca (np. 13, 33, 53, 73, 93)
    pesel_invalid_month = "00130100000" # Rok 1900, miesiąc 13
    assert extract_info_from_pesel(pesel_invalid_month) is None

    pesel_invalid_month_2000 = "00330100000" # Rok 2000, miesiąc 33
    assert extract_info_from_pesel(pesel_invalid_month_2000) is None
