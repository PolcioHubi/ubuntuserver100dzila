# Użyj oficjalnego, lekkiego obrazu Python jako bazy
FROM python:3.11-slim

# Ustaw zmienne środowiskowe, aby Python nie buforował stdout i stderr
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /app

# Ustaw katalog roboczy wewnątrz kontenera
WORKDIR /app

# Skopiuj plik z zależnościami i zainstaluj je
# Robimy to jako osobny krok, aby wykorzystać cache Dockera
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Skopiuj resztę kodu aplikacji do katalogu roboczego
COPY . .

# Upewnij się, że katalogi na dane istnieją wewnątrz kontenera
# Chociaż będziemy używać wolumenów, to dobra praktyka
RUN mkdir -p /app/auth_data /app/user_data /app/logs

# Wystaw port, na którym Gunicorn będzie nasłuchiwał
EXPOSE 5000

# Polecenie, które zostanie wykonane przy uruchamianiu kontenera
# Najpierw uruchamiamy migracje, a potem startujemy serwer Gunicorn
# To zapewnia, że baza danych jest zawsze aktualna przy starcie kontenera.
ENV FLASK_APP=app.py

# Polecenie, które zostanie wykonane przy uruchamianiu kontenera
# Najpierw uruchamiamy migracje, a potem startujemy serwer Gunicorn
CMD ["sh", "-c", "flask db upgrade && gunicorn --workers 3 --bind 0.0.0.0:5000 wsgi:application"]

