# Mobywatel-Creator: Ostateczny Manifest Techniczny

---

## Rozdział 1: Wprowadzenie do Ekosystemu Aplikacji

### 1.1. Nadrzędna Filozofia Projektu: Inżynieria Oprogramowania w Praktyce

Projekt **Mobywatel-Creator** został powołany do życia nie jako produkt komercyjny, lecz jako **żywe laboratorium inżynierii oprogramowania**. Jego fundamentalnym celem jest służenie jako transparentny i dogłębny **materiał dydaktyczny**, który dekonstruuje proces tworzenia nowoczesnej, bezpiecznej i gotowej do wdrożenia aplikacji webowej. Każda linia kodu, każda decyzja architektoniczna i każdy plik konfiguracyjny zostały świadomie wybrane, aby ilustrować kluczowe zasady i wzorce, takie jak SOLID, DRY, separacja odpowiedzialności (Separation of Concerns) oraz wielowarstwowe podejście do bezpieczeństwa (Defense in Depth).

Niniejszy dokument nie jest zwykłym plikiem `README.md`. Jest to **kompletny manifest techniczny**, zaprojektowany, by być jedynym źródłem prawdy (`Single Source of Truth`) dla deweloperów, administratorów i analityków pragnących zrozumieć ten system na poziomie atomowym.

### 1.2. Dekonstrukcja Architektury: Podróż Żądania przez Stos Technologiczny

Architektura systemu jest świadomą implementacją **modelu warstwowego**, gdzie każda warstwa ma ściśle zdefiniowane obowiązki, minimalizując zależności i maksymalizując spójność (cohesion). Prześledźmy podróż typowego żądania API, aby zrozumieć tę separację w praktyce:

1.  **Warstwa Brzegowa (Edge Layer) - `Nginx`**:
    *   Żądanie od klienta (np. `POST /login`) uderza najpierw w serwer Nginx na porcie 80 lub 443.
    *   Nginx, działając jako **Reverse Proxy**, natychmiast podejmuje decyzje: jeśli to żądanie do `/static/*`, serwuje plik bezpośrednio z dysku (maksymalna wydajność). Jeśli nie, przekazuje żądanie dalej.
    *   W środowisku produkcyjnym, to Nginx odpowiada za **terminację SSL**, deszyfrując ruch HTTPS i przekazując czyste żądanie HTTP do warstwy aplikacji. Dodaje również kluczowe nagłówki bezpieczeństwa (`X-Frame-Options`, `HSTS` etc.).

2.  **Warstwa Serwera Aplikacji (Application Server Layer) - `Gunicorn`**:
    *   Żądanie jest odbierane przez jeden z wolnych procesów roboczych (workerów) Gunicorna, który nasłuchuje na wewnętrznym porcie (np. 5000).
    *   Gunicorn tłumaczy surowe żądanie HTTP na **standard WSGI (Web Server Gateway Interface)**, tworząc środowisko i obiekt `request`, które są zrozumiałe dla Flaska.

3.  **Warstwa Aplikacji / Kontrolera (Application/Controller Layer) - `Flask` (`app.py`)**:
    *   Flask, na podstawie ścieżki URL (`/login`), dopasowuje żądanie do odpowiedniej funkcji-widoku (np. `def login():`).
    *   Flask parsuje dane z żądania (np. JSON z loginem i hasłem) i udostępnia je w obiekcie `request`.
    *   **Kluczowy moment:** Funkcja `login()` nie implementuje logiki uwierzytelniania. Jej jedynym zadaniem jest **orkiestracja** - wywołuje odpowiednią metodę z `UserAuthManager` (`auth_manager.authenticate_user(...)`), przekazując jej sparsowane dane.

4.  **Warstwa Usług / Logiki Biznesowej (Service/Business Logic Layer) - `user_auth.py`**:
    *   Metoda `authenticate_user` otrzymuje czyste dane (login, hasło).
    *   Wykonuje serię operacji biznesowych: wyszukuje użytkownika w bazie, sprawdza jego status, a następnie wywołuje wewnętrzną, kryptograficzną funkcję `_check_password`.
    *   Zwraca jednoznaczną odpowiedź (np. `(True, "Logowanie pomyślne")`) do warstwy aplikacji.

5.  **Warstwa Dostępu do Danych (Data Access Layer) - `database.py` & `sqlite3`**:
    *   Metody w `user_auth.py` używają `_managed_connection`, aby uzyskać bezpieczne połączenie z bazą danych zdefiniowane w `database.py`.
    *   Wykonywane są konkretne zapytania SQL (`SELECT`, `UPDATE`), a wyniki są zwracane do warstwy usług.

6.  **Podróż Powrotna (Odpowiedź):**
    *   `user_auth.py` zwraca wynik do `app.py`.
    *   `app.py` na podstawie wyniku zarządza **sesją** (`session['user_logged_in'] = True`) i konstruuje odpowiedź JSON (`jsonify(...)`).
    *   Odpowiedź jest przekazywana przez Gunicorna do Nginxa, a następnie do klienta.

---

## Rozdział 2: Analiza Atomowa Modułów Kodu Źródłowego

### 2.1. `database.py`: Kontrakt Schematu Danych

Ten plik to **kamień węgielny** całej aplikacji. Nie zawiera logiki, lecz **definicję i kontrakt**, z którego korzystają wszystkie inne moduły operujące na danych.

-   **`get_db_connection()`**: Ta funkcja to **fabryka połączeń**. Jej najważniejszą cechą jest linia `conn.row_factory = sqlite3.Row`. Bez tej linii, każde zapytanie `SELECT` zwracałoby krotkę (tuple), np. `('admin', '$2b$12$...')`. Dostęp do danych wymagałby użycia magicznych indeksów (`user[0]`, `user[1]`), co jest koszmarem w utrzymaniu. Dzięki `sqlite3.Row`, wynik jest obiektem, który pozwala na dostęp przez nazwy kolumn (`user['username']`, `user['password']`), co czyni kod **samo-dokumentującym się** i odpornym na zmiany kolejności kolumn w tabeli.

-   **`init_db()`**: To jest **skrypt migracyjny w najprostszej postaci**. Definiuje on **kanoniczny schemat bazy danych**. Każda kolumna jest precyzyjnie zdefiniowana:
    *   `username TEXT PRIMARY KEY UNIQUE NOT NULL`: `TEXT` to typ danych. `PRIMARY KEY` oznacza, że jest to główny identyfikator wiersza. `UNIQUE` i `NOT NULL` to **ograniczenia (constraints)**, które są egzekwowane na poziomie bazy danych, zapewniając integralność danych, nawet jeśli logika aplikacji zawiedzie.
    *   `is_active INTEGER NOT NULL DEFAULT 1`: Użycie `INTEGER` jako flagi boolowskiej (0/1) jest standardem w SQLite. `DEFAULT 1` oznacza, że każdy nowo utworzony użytkownik jest domyślnie aktywny, co upraszcza logikę rejestracji.

### 2.2. `user_auth.py`: Hermetyzacja Logiki Tożsamości

Ta klasa to podręcznikowy przykład wzorca **Fasady (Facade)**. Ukrywa ona całą złożoność interakcji z bazą danych, hashowania i walidacji za czystym, spójnym interfejsem.

-   **`_managed_connection()`**: To nie jest zwykła funkcja, to **menedżer kontekstu** (`@contextmanager`). Gwarantuje on **transakcyjność i bezpieczeństwo zasobów**. Blok `try...except...finally` zapewnia, że nawet w przypadku wystąpienia błędu w połowie operacji, transakcja zostanie wycofana (`rollback`), a połączenie z bazą danych zostanie zamknięte, zapobiegając wyciekom zasobów.

-   **`_hash_password(password)`**: Ta pozornie prosta funkcja jest **krytyczna dla bezpieczeństwa**. `bcrypt.gensalt()` generuje losową sól, która jest następnie łączona z hasłem przed hashowaniem. Oznacza to, że nawet jeśli dziesięciu użytkowników ustawi to samo hasło "password123", w bazie danych zostanie zapisanych dziesięć **różnych** hashy. To całkowicie uniemożliwia ataki słownikowe i z użyciem tęczowych tablic (rainbow tables).

-   **`register_user(username, password, access_key)`**: Ta metoda to **transakcja biznesowa**. Jej logika jest sekwencyjna i defensywna:
    1.  **Pre-walidacja:** Sprawdza poprawność klucza i danych wejściowych. Zwraca wczesny błąd, jeśli warunki nie są spełnione.
    2.  **Unikalność:** Wykonuje zapytanie `SELECT`, aby upewnić się, że nazwa użytkownika nie jest zajęta. Jest to ochrona przed warunkiem wyścigu (race condition).
    3.  **Wykonanie:** Jeśli wszystkie warunki są spełnione, wykonuje operacje zapisu w ramach transakcji zarządzanej przez `_managed_connection`.

### 2.3. `app.py`: Centrum Dowodzenia Aplikacją

Ten plik jest **kontrolerem** i **integratorem**. Jego zadaniem jest przyjmowanie żądań, delegowanie zadań do odpowiednich modułów i formatowanie odpowiedzi.

-   **`@limiter.limit(...)`**: Ten dekorator to implementacja wzorca **Throttling (dławienia)**. Chroni on kluczowe, publicznie dostępne endpointy (`/login`, `/register`) przed zautomatyzowanymi atakami siłowymi (brute-force) i prostymi atakami DoS, ograniczając liczbę żądań z jednego adresu IP w danym oknie czasowym.

-   **`replace_html_data(input_soup, new_data)`**: To jest **silnik transformacji treści**. Jego siła leży w użyciu `BeautifulSoup`, które buduje w pamięci drzewo DOM dokumentu. Wyszukiwanie elementów po klasach i relacjach (np. `find_next_sibling`) jest znacznie bardziej elastyczne i odporne na zmiany niż operacje na surowym tekście. Każda operacja modyfikacji jest opakowana w warunek `if`, co zapobiega awarii całej funkcji, jeśli jeden z oczekiwanych tagów nie zostanie znaleziony w szablonie.

-   **Logika endpointu `/` (`POST`):** To najbardziej złożona operacja w aplikacji. Jej wewnętrzny przepływ jest następujący:
    1.  **Identyfikacja Kontekstu:** Pobiera `user_name` z formularza, który jest kluczem do całej operacji.
    2.  **Zarządzanie Stanem Pliku:** Sprawdza, czy plik `dowodnowy.html` już istnieje dla danego użytkownika. Jeśli tak, staje się on bazą do modyfikacji. Jeśli nie, używany jest domyślny szablon `pasted_content.txt`. To pozwala na iteracyjne modyfikacje dokumentu przez użytkownika.
    3.  **Obsługa Uploadu z Optymalizacją:** To jest kluczowy fragment. Zamiast ślepo nadpisywać plik, system najpierw oblicza hash SHA256 przesyłanej zawartości. Następnie porównuje go z hashem pliku już istniejącego na dysku. **Operacja zapisu I/O, która jest kosztowna, jest wykonywana tylko wtedy, gdy hashe się różnią.** To inteligentna optymalizacja, która oszczędza zasoby dyskowe i cykle procesora.

---

## Rozdział 3: Podręcznik Operacyjny Stosu Produkcyjnego

### 3.1. `mobywatel.service`: Konfiguracja Uruchomienia Gunicorna

W środowisku produkcyjnym, Gunicorn nie jest uruchamiany ręcznie, lecz poprzez usługę `systemd` zdefiniowaną w `/etc/systemd/system/mobywatel.service`. Kluczowe parametry są zdefiniowane bezpośrednio w poleceniu `ExecStart`:

-   **`--workers 3`**: Oznacza, że Gunicorn może obsłużyć do 3 żądań **jednocześnie**, w równoległych procesach. Jest to absolutnie kluczowe dla skalowalności aplikacji pod obciążeniem.
-   **`--bind unix:/var/www/mobywatel/mobywatel.sock`**: Gunicorn nie nasłuchuje na porcie sieciowym (np. 5000), lecz tworzy **gniazdo (socket) Unixa**. Jest to bezpieczniejsza i nieco wydajniejsza metoda komunikacji międzyprocesowej, gdy Nginx i Gunicorn działają na tej samej maszynie.
-   **`--access-logfile` i `--error-logfile`**: Te flagi, dodane w celu centralizacji logowania, przekierowują wszystkie logi dostępu i błędów Gunicorna do dedykowanych plików w katalogu `logs/` projektu.

### 3.2. `nginx_config.conf`: Konfiguracja Bezpieczeństwa i Szybkości

-   **`location /static { ... }`**: Ta dyrektywa jest **krytyczna dla wydajności**. Mówi Nginxowi: "Jeśli URL zaczyna się od `/static`, nie zawracaj głowy aplikacji Flask. Znajdź plik w katalogu podanym w `alias` i wyślij go bezpośrednio do klienta z nagłówkiem `Cache-Control`, który każe przeglądarce przechowywać go przez rok". To odciąża aplikację i sprawia, że strona ładuje się błyskawicznie.
-   **`location / { ... }`**: Ta sekcja to **tunel do aplikacji**. `proxy_pass` przekazuje żądanie do Gunicorna. Nagłówki `proxy_set_header` są niezbędne, aby aplikacja Flask otrzymała prawdziwe informacje o oryginalnym żądaniu (np. `Host`, `X-Real-IP`), a nie informacje o proxy Nginx.
-   **`server_tokens off;`**: Prosta, ale ważna dyrektywa bezpieczeństwa. Ukrywa ona dokładną wersję Nginxa w nagłówkach odpowiedzi, co utrudnia atakującym wyszukiwanie znanych luk w konkretnej wersji serwera.

### 3.3. `systemd_service.service`: Gwarant Dostępności

Plik usługi `systemd` zapewnia, że aplikacja jest zarządzana przez system operacyjny, co gwarantuje jej stabilność i ciągłość działania.

-   **`User=ubuntu`**: Aplikacja działa jako użytkownik systemowy `ubuntu`. W idealnym, zahartowanym środowisku byłby to użytkownik z jeszcze mniejszymi uprawnieniami (np. `www-data`), ale obecna konfiguracja wciąż zapewnia dobrą izolację od użytkownika `root`.
-   **`Restart=always`**: To jest **gwarancja wysokiej dostępności (High Availability)**. Jeśli aplikacja ulegnie awarii z jakiegokolwiek powodu (błąd w kodzie, brak pamięci), `systemd` natychmiast podejmie próbę jej ponownego uruchomienia.
-   **`WorkingDirectory`**: Zapewnia, że aplikacja jest uruchamiana z odpowiedniego katalogu, co jest kluczowe dla poprawnego działania względnych ścieżek do plików.

---

## Rozdział 4: Wnioski Końcowe

Ten dokument jest kulminacją głębokiej analizy projektu Mobywatel-Creator. Każdy element, od pojedynczej linii kodu po globalną architekturę, został zbadany i wyjaśniony. Projekt ten, wraz z niniejszą dokumentacją, stanowi kompletny, samowystarczalny zasób edukacyjny, demonstrujący, jak teoria inżynierii oprogramowania przekłada się na praktyczną, działającą i bezpieczną aplikację webową. Jest to ostateczny przewodnik, który powinien służyć jako solidny fundament dla każdego, kto chce zrozumieć, używać lub rozwijać ten system.

## Rozdział 5: Ważne Uwagi Dotyczące Wdrożenia i Konfiguracji

Niniejszy projekt został zaprojektowany z myślą o elastyczności i bezpieczeństwie, jednak wymaga **świadomego dostosowania** do konkretnego środowiska wdrożenia. Poniżej przedstawiono kluczowe punkty, które należy zweryfikować i zmodyfikować przed uruchomieniem aplikacji w środowisku produkcyjnym:

1.  **Ścieżki Projektu (`PROJECT_ROOT`)**: W plikach takich jak `install_script.sh`, `start_server.sh` oraz `systemd_service.service` zdefiniowano zmienne lub ścieżki bezwzględne do katalogu głównego projektu. **MUSISZ** zweryfikować i dostosować te ścieżki, aby odpowiadały rzeczywistej lokalizacji projektu na Twoim serwerze (np. `/var/www/mobywatelcreator` lub `/opt/mobywatelcreator`).

2.  **Konfiguracja Nginx (`nginx_config.conf`)**:
    *   **`server_name`**: Zmień `80.208.227.170` oraz `your-domain.com` na rzeczywistą nazwę domeny lub adres IP Twojego serwera.
    *   **Certyfikaty SSL**: Sekcje `ssl_certificate` i `ssl_certificate_key` wskazują na pliki certyfikatów. **MUSISZ** uzyskać własne certyfikaty SSL (np. za pomocą Certbot dla Let's Encrypt) i zaktualizować te ścieżki. Po skonfigurowaniu HTTPS, odkomentuj blok przekierowania HTTP na HTTPS.
    *   **Nagłówki Bezpieczeństwa**: Odkomentuj i włącz wszystkie nagłówki bezpieczeństwa (`X-Frame-Options`, `HSTS` itd.) po pomyślnym skonfigurowaniu HTTPS.

3.  **Konfiguracja Gunicorn**:
    *   Parametry uruchomieniowe Gunicorna (takie jak liczba workerów) są zdefiniowane bezpośrednio w pliku `/etc/systemd/system/mobywatel.service`. Plik `gunicorn_config.py` w repozytorium jest przykładem, ale nie jest używany w obecnej konfiguracji.

4.  **Konfiguracja Systemd**:
    *   Upewnij się, że użytkownik i grupa zdefiniowani w pliku `/etc/systemd/system/mobywatel.service` (np. `User=ubuntu`) istnieją w Twoim systemie.
    *   W przeciwieństwie do szablonu w repozytorium, produkcyjna usługa `systemd` nie używa zaawansowanych opcji `ReadWritePaths`. Uprawnienia do zapisu w katalogach `user_data`, `auth_data` i `logs` muszą być zapewnione na poziomie uprawnień systemu plików dla użytkownika, pod którym działa usługa.

5.  **Sekrety i Hasła**:
    *   **`SECRET_KEY`**: W `production_config.py` klucz `SECRET_KEY` powinien być unikalny i tajny. **NIGDY** nie używaj domyślnego klucza w produkcji. Użyj zmiennych środowiskowych lub bezpiecznego menedżera sekretów.
    *   **`ADMIN_USERNAME` i `ADMIN_PASSWORD`**: Zmień domyślne dane logowania administratora na silne, unikalne wartości. Najlepiej, aby były one również zarządzane jako sekrety.

6.  **Baza Danych**:
    *   Domyślnie używana jest baza SQLite. W przypadku większych wdrożeń lub potrzeby skalowalności, rozważ migrację do bardziej robustnej bazy danych (np. PostgreSQL, MySQL) i odpowiednio zaktualizuj konfigurację.

7.  **Zarządzanie Aplikacją w Środowisku Produkcyjnym**:
    *   **Restartowanie Usług**: Aplikacja i serwer webowy są zarządzane przez `systemd`. Po wprowadzeniu jakichkolwiek zmian w kodzie aplikacji lub konfiguracji Gunicorna, **musisz** zrestartować główną usługę aplikacji, aby zmiany weszły w życie. Użyj polecenia:
        ```bash
        sudo systemctl restart mobywatel.service
        ```
    *   Po wprowadzeniu zmian w konfiguracji Nginxa, **musisz** zrestartować usługę Nginxa:
        ```bash
        sudo systemctl restart nginx.service
        ```
    *   **Scentralizowane Logi**: Wszystkie logi (aplikacji, Gunicorna i Nginxa) są zapisywane w katalogu `logs/` w głównym folderze projektu. Jest to pierwsze miejsce, w którym należy szukać informacji diagnostycznych w przypadku problemów.

**Niewłaściwa konfiguracja tych elementów może prowadzić do problemów z bezpieczeństwem, wydajnością lub niedostępnością aplikacji.** Zawsze testuj konfigurację w środowisku stagingowym przed wdrożeniem na produkcję.
