import os
from app import app, db
from models import File

def diagnose_files_in_db():
    """
    Łączy się z bazą danych aplikacji i wyświetla zawartość tabeli 'files'.
    """
    with app.app_context():
        print("--- Diagnostyka Tabeli Plików w Bazie Danych ---")
        
        all_files = File.query.all()
        
        if not all_files:
            print("Baza danych nie zawiera żadnych rekordów o plikach. Wszystko jest w porządku.")
            return

        print(f"Znaleziono {len(all_files)} rekordów o plikach w bazie danych:")
        print("-" * 50)
        for file_entry in all_files:
            # Sprawdź, czy plik fizycznie istnieje
            file_exists = os.path.exists(file_entry.filepath)
            print(f"  ID: {file_entry.id}")
            print(f"  Użytkownik: {file_entry.user_username}")
            print(f"  Nazwa Pliku: {file_entry.filename}")
            print(f"  Ścieżka w DB: {file_entry.filepath}")
            print(f"  Czy istnieje na dysku? {'TAK' if file_exists else 'NIE - OSIEROCONY REKORD!'}")
            print("-" * 20)

def clear_orphan_files():
    """
    Znajduje i usuwa z bazy danych wszystkie rekordy o plikach, które
    nie istnieją już fizycznie na dysku.
    """
    with app.app_context():
        print("\n--- Czyszczenie Osieroconych Rekordów Plików ---")
        all_files = File.query.all()
        orphans_found = 0
        for file_entry in all_files:
            if not os.path.exists(file_entry.filepath):
                print(f"Usuwanie osieroconego rekordu dla pliku: {file_entry.filepath}")
                db.session.delete(file_entry)
                orphans_found += 1
        
        if orphans_found > 0:
            db.session.commit()
            print(f"Pomyślnie usunięto {orphans_found} osieroconych rekordów.")
        else:
            print("Nie znaleziono żadnych osieroconych rekordów do usunięcia.")

if __name__ == "__main__":
    # Sprawdź, czy podano argument --clear
    import sys
    if "--clear" in sys.argv:
        clear_orphan_files()
    else:
        diagnose_files_in_db()
        print("\nAby usunąć osierocone rekordy, uruchom skrypt z flagą: python diagnose_files.py --clear")
