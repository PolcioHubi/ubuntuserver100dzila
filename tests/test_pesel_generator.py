import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from pesel_generator import generate_pesel, validate_pesel, extract_info_from_pesel


def test_generate_pesel_male():
    birth_date = "01.01.1990"
    gender = "Mężczyzna"
    pesel = generate_pesel(birth_date, gender)
    assert len(pesel) == 11
    assert validate_pesel(pesel) is True
    info = extract_info_from_pesel(pesel)
    assert info is not None, "Info should not be None for valid PESEL"
    assert info["gender"] == gender
    assert info["birth_date"] == birth_date
    assert info["year"] == 1990
    assert info["month"] == 1
    assert info["day"] == 1


def test_generate_pesel_female():
    birth_date = "01.01.1990"
    gender = "Kobieta"
    pesel = generate_pesel(birth_date, gender)
    assert len(pesel) == 11
    assert validate_pesel(pesel) is True
    info = extract_info_from_pesel(pesel)
    assert info is not None, "Info should not be None for valid PESEL"
    assert info["gender"] == gender
    assert info["birth_date"] == birth_date
    assert info["year"] == 1990
    assert info["month"] == 1
    assert info["day"] == 1


def test_generate_pesel_different_century():
    birth_date = "01.01.2000"
    gender = "Mężczyzna"
    pesel = generate_pesel(birth_date, gender)
    assert len(pesel) == 11
    assert validate_pesel(pesel) is True
    info = extract_info_from_pesel(pesel)
    assert info is not None, "Info should not be None for valid PESEL"
    assert info["birth_date"] == birth_date
    assert info["year"] == 2000
    assert info["month"] == 1
    assert info["day"] == 1


def test_validate_pesel_invalid_length():
    assert validate_pesel("123") is False


def test_validate_pesel_invalid_checksum():
    # A valid PESEL with one digit changed to make checksum invalid
    assert validate_pesel("90010112346") is False


def test_validate_pesel_dynamic_invalid_checksum():
    # Generate a valid PESEL
    valid_pesel = generate_pesel("01.01.1990", "Mężczyzna")
    # Change a non-checksum digit to make it invalid
    invalid_pesel = list(valid_pesel)
    invalid_pesel[0] = str((int(invalid_pesel[0]) + 1) % 10)  # Change first digit
    invalid_pesel = "".join(invalid_pesel)
    assert validate_pesel(invalid_pesel) is False


def test_extract_info_from_pesel_invalid_pesel():
    assert extract_info_from_pesel("invalid") is None


def test_extract_info_from_pesel_male():
    pesel = generate_pesel("15.03.1985", "Mężczyzna")
    info = extract_info_from_pesel(pesel)
    assert info is not None, "Info should not be None for valid PESEL"
    assert info["birth_date"] == "15.03.1985"
    assert info["gender"] == "Mężczyzna"


def test_extract_info_from_pesel_female():
    pesel = generate_pesel("20.07.1995", "Kobieta")
    info = extract_info_from_pesel(pesel)
    assert info is not None, "Info should not be None for valid PESEL"
    assert info["birth_date"] == "20.07.1995"
    assert info["gender"] == "Kobieta"


def test_extract_info_from_pesel_21st_century():
    pesel = generate_pesel("10.11.2005", "Mężczyzna")
    info = extract_info_from_pesel(pesel)
    assert info is not None, "Info should not be None for valid PESEL"
    assert info["birth_date"] == "10.11.2005"


def test_generate_pesel_invalid_date():
    with pytest.raises(ValueError, match="Nieprawidłowa data"):
        generate_pesel("32.01.1990", "Mężczyzna")


def test_generate_pesel_unsupported_year():
    with pytest.raises(
        ValueError, match="Rok 1700 nie jest obsługiwany przez algorytm PESEL"
    ):
        generate_pesel("01.01.1700", "Mężczyzna")


def test_generate_pesel_leap_year():
    # Rok przestępny
    pesel_leap = generate_pesel("29.02.2000", "Kobieta")
    assert validate_pesel(pesel_leap) is True
    info_leap = extract_info_from_pesel(pesel_leap)
    assert info_leap is not None, "Info should not be None for valid PESEL"
    assert info_leap["birth_date"] == "29.02.2000"

    # Rok nieprzestępny (1900 nie był przestępny dla PESEL)
    with pytest.raises(
        ValueError,
        match="Błąd w generowaniu PESEL: 29 lutego 1900 nie jest prawidłową datą dla PESEL.",
    ):
        generate_pesel("29.02.1900", "Mężczyzna")


def test_generate_pesel_invalid_month_day():
    with pytest.raises(ValueError, match="Nieprawidłowa data"):
        generate_pesel("31.02.1990", "Mężczyzna")  # Luty ma max 29 dni
    with pytest.raises(ValueError, match="Nieprawidłowa data"):
        generate_pesel("32.01.1990", "Kobieta")  # Dzień poza zakresem
    with pytest.raises(ValueError, match="Nieprawidłowa data"):
        generate_pesel("01.13.1990", "Mężczyzna")  # Miesiąc poza zakresem


def test_validate_pesel_non_digit_characters():
    assert validate_pesel("1234567890A") is False
    assert validate_pesel("ABCDEFGHIJK") is False
    assert validate_pesel("900101123-5") is False


def test_extract_info_from_pesel_invalid_format():
    assert extract_info_from_pesel("123") is None
    assert extract_info_from_pesel("1234567890A") is None
    assert extract_info_from_pesel("invalid_pesel_string") is None


def test_generate_pesel_edge_years():
    # 1800s
    pesel_1899 = generate_pesel("01.01.1899", "Mężczyzna")
    assert validate_pesel(pesel_1899) is True
    info_1899 = extract_info_from_pesel(pesel_1899)
    assert info_1899 is not None, "Info should not be None for valid PESEL"
    assert info_1899["year"] == 1899

    # 1900s
    pesel_1900 = generate_pesel("01.01.1900", "Kobieta")
    assert validate_pesel(pesel_1900) is True
    info_1900 = extract_info_from_pesel(pesel_1900)
    assert info_1900 is not None, "Info should not be None for valid PESEL"
    assert info_1900["year"] == 1900

    # 2000s
    pesel_2000 = generate_pesel("01.01.2000", "Mężczyzna")
    assert validate_pesel(pesel_2000) is True
    info_2000 = extract_info_from_pesel(pesel_2000)
    assert info_2000 is not None, "Info should not be None for valid PESEL"
    assert info_2000["year"] == 2000

    # 2099
    pesel_2099 = generate_pesel("31.12.2099", "Kobieta")
    assert validate_pesel(pesel_2099) is True
    info_2099 = extract_info_from_pesel(pesel_2099)
    assert info_2099 is not None, "Info should not be None for valid PESEL"
    assert info_2099["year"] == 2099

def test_get_month_with_century_modifier_unsupported_year():
    with pytest.raises(ValueError, match="Rok 1799 nie jest obsługiwany przez algorytm PESEL"):
        generate_pesel("01.01.1799", "Mężczyzna")

def test_extract_info_from_pesel_invalid_month():
    # This PESEL has an invalid month field (e.g., 13)
    invalid_pesel = "90130112345"
    assert extract_info_from_pesel(invalid_pesel) is None
