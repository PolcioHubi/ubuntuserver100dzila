#!/bin/bash

# ==============================================================================
# Skrypt do pełnego wdrożenia aplikacji Flask/Gunicorn z Nginx, SSL i Logowaniem
# WERSJA OSTATECZNA PANCERNA v4 (2025-08-08)
# Zaktualizowano Content-Security-Policy, aby zezwolić na skrypty z cdn.jsdelivr.net
# ==============================================================================

# Zatrzymaj skrypt w przypadku błędu
set -e

# --- ZMIENNE KONFIGURACYJNE ---
SERVICE_NAME="mobywatel"
PROJECT_USER="mobywatel_user"
DEST_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOMAIN="185-167-99-62.cloud-xip.com"
SSL_EMAIL="polciovps@atomicmail.io"
GUNICORN_WORKERS=$((2 * $(nproc) + 1))
# POPRAWKA: Polityka CSP dopasowana do potrzeb aplikacji (QR codes, fonty zewnętrzne, Service Worker)
# WAŻNE: connect-src musi zawierać api.qrserver.com dla Fetch API w Service Worker!
# WAŻNE: worker-src 'self' jest wymagany dla Service Workera!
CSP_HEADER="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com https://185-167-99-62.cloud-xip.com/cdn-cgi/; style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; img-src 'self' data: blob: https://api.qrserver.com; font-src 'self' data:; connect-src 'self' https://api.qrserver.com https://challenges.cloudflare.com; frame-src 'self' https://challenges.cloudflare.com; manifest-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self';"


echo ">>> START: Rozpoczynanie wdrożenia aplikacji $SERVICE_NAME..."
echo ">>> Katalog aplikacji (uruchomienie z źródła): $DEST_DIR"
echo ">>> Użyta liczba workerów Gunicorna: $GUNICORN_WORKERS"

# --- KROK 0: Utworzenie dedykowanego użytkownika (jeśli nie istnieje) ---
echo ">>> KROK 0: Sprawdzanie i tworzenie użytkownika systemowego $PROJECT_USER..."
if ! id "$PROJECT_USER" &>/dev/null; then
    sudo useradd -r -s /bin/false $PROJECT_USER
    echo "Użytkownik $PROJECT_USER został utworzony."
else
    echo "Użytkownik $PROJECT_USER już istnieje."
fi

# --- KROK 1: Instalacja podstawowych zależności ---
echo ">>> KROK 1: Instalowanie Nginx, Pip, Venv i Certbota..."
sudo apt-get update
sudo apt-get install -y nginx python3-pip python3-venv certbot python3-certbot-nginx redis-server

# Upewnij się, że Redis jest uruchomiony i włączony przy starcie systemu
echo ">>> Upewnianie się, że Redis jest uruchomiony i włączony..."
sudo systemctl start redis-server
sudo systemctl enable redis-server

# --- KROK 1.5: Dodanie użytkownika Nginx do grupy projektu ---
echo ">>> KROK 1.5: Dodawanie użytkownika www-data do grupy $PROJECT_USER..."
sudo usermod -aG $PROJECT_USER www-data

# --- KROK 2: Przygotowanie katalogu aplikacji ---
echo ">>> KROK 2: Ustawianie właściciela katalogu $DEST_DIR..."
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR
echo ">>> KROK 2.5: Tworzenie katalogów na logi i dane..."
sudo mkdir -p $DEST_DIR/logs
sudo mkdir -p $DEST_DIR/auth_data
sudo mkdir -p $DEST_DIR/user_data
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/logs
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/auth_data
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/user_data
echo ">>> KROK 2.6: Ustawianie bezpiecznych uprawnień do plików i folderów..."
sudo find $DEST_DIR -type d -exec chmod 750 {} \;
sudo find $DEST_DIR -type f -exec chmod 640 {} \;
sudo chmod +x $0

# --- KROK 3: Konfiguracja środowiska wirtualnego i zależności ---
echo ">>> KROK 3: Uruchamianie konfiguracji środowiska Python..."
sudo -u "$PROJECT_USER" bash -c "
set -e
echo '--- Tworzenie pliku .env z sekretami...'
cat > '$DEST_DIR/.env' <<EOF
SECRET_KEY=\$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=\$(openssl rand -hex 16)
EOF
echo '--- Tworzenie środowiska wirtualnego w $DEST_DIR/venv...'
python3 -m venv '$DEST_DIR/venv'
chmod -R +x '$DEST_DIR/venv/bin'
echo '--- Aktualizacja pip i instalacja zależności z requirements.txt...'
'$DEST_DIR/venv/bin/pip' install --upgrade pip
'$DEST_DIR/venv/bin/pip' install -r '$DEST_DIR/requirements.txt'
echo '--- Wykonywanie migracji bazy danych...'
rm -rf '$DEST_DIR/migrations'
rm -f '$DEST_DIR/auth_data/database.db'
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db init
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db migrate -m 'Initial deployment migration'
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db upgrade
"

# --- KROK 4: Konfiguracja usługi Systemd dla Gunicorn ---
echo ">>> KROK 4: Konfiguracja usługi Systemd dla Gunicorn..."
sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Gunicorn instance to serve $SERVICE_NAME
After=network.target
[Service]
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$DEST_DIR
EnvironmentFile=$DEST_DIR/.env
Environment="PATH=$DEST_DIR/venv/bin"
ExecStart=$DEST_DIR/venv/bin/gunicorn --workers $GUNICORN_WORKERS --bind unix:$DEST_DIR/${SERVICE_NAME}.sock -m 007 --timeout 120 --access-logfile $DEST_DIR/logs/gunicorn_access.log --error-logfile $DEST_DIR/logs/gunicorn_error.log wsgi:application
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# --- KROK 4.5: Tworzenie dedykowanego pliku z nagłówkami bezpieczeństwa ---
echo ">>> KROK 4.5: Tworzenie pliku z nagłówkami bezpieczeństwa..."
sudo mkdir -p /etc/nginx/snippets
sudo tee /etc/nginx/snippets/security-headers.conf > /dev/null <<EOF
# HSTS (max-age = 2 lata), wymusza HTTPS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
# Ochrona przed MIME sniffing
add_header X-Content-Type-Options "nosniff" always;
# Ochrona przed clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;
# Ulepszona polityka Referrer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
# Blokowanie niechcianych funkcji przeglądarki (zezwolenie na kamerę dla QR)
add_header Permissions-Policy "camera=(self), microphone=(), geolocation=()" always;
# Polityka bezpieczeństwa treści
add_header Content-Security-Policy "$CSP_HEADER" always;
EOF

# --- KROK 4.6: Zwiększenie limitu rozmiaru przesyłanych plików ---
echo ">>> KROK 4.6: Konfiguracja limitu rozmiaru plików (client_max_body_size)..."
sudo tee /etc/nginx/snippets/upload-limits.conf > /dev/null <<EOF
# Zwiększenie limitu przesyłanych plików do 100MB (dla importu backupów)
client_max_body_size 100M;
EOF

# --- KROK 5: Konfiguracja Nginx (WSTĘPNA, tylko HTTP) ---
echo ">>> KROK 5: Tworzenie WSTĘPNEJ konfiguracji Nginx dla domeny $DOMAIN (tylko port 80)..."
sudo rm -f /etc/nginx/sites-available/$SERVICE_NAME
sudo rm -f /etc/nginx/sites-enabled/$SERVICE_NAME
# Tworzymy BARDZO prostą konfigurację, żeby Certbot ją znalazł i poprawnie zmodyfikował.
sudo tee /etc/nginx/sites-available/$SERVICE_NAME > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    # Zwiększony limit rozmiaru przesyłanych plików
    include /etc/nginx/snippets/upload-limits.conf;
    
    location / {
        proxy_pass http://unix:$DEST_DIR/${SERVICE_NAME}.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Włącz nową konfigurację i usuń domyślną
sudo ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

# --- KROK 6: Uruchomienie usług ---
echo ">>> KROK 6: Przeładowanie i uruchomienie usług..."
sudo systemctl daemon-reload
sudo systemctl restart $SERVICE_NAME
sudo systemctl enable $SERVICE_NAME

# Sprawdzenie konfiguracji Nginx i restart
echo ">>> Sprawdzanie i restartowanie Nginx..."
sudo nginx -t
sudo systemctl restart nginx

# --- KROK 7: Konfiguracja SSL i HTTP/2 za pomocą Certbota ---
echo ">>> KROK 7: Uruchamianie Certbota dla $DOMAIN..."
sudo certbot --nginx --non-interactive --agree-tos -m "$SSL_EMAIL" -d "$DOMAIN" --redirect

# --- KROK 8: Wstrzykiwanie ostatecznych nagłówków bezpieczeństwa do konfiguracji SSL ---
echo ">>> KROK 8: Wstrzykiwanie ostatecznych nagłówków bezpieczeństwa i limitów do konfiguracji SSL..."
CONFIG_FILE="/etc/nginx/sites-available/$SERVICE_NAME"
# Używamy sed do wstawienia linii 'include ...' zaraz po linii 'server_name ...'
sudo sed -i "/server_name $DOMAIN/a include /etc/nginx/snippets/security-headers.conf;" $CONFIG_FILE
# Dodajemy również limity uploadów, jeśli jeszcze nie są w konfiguracji SSL
if ! grep -q "upload-limits.conf" "$CONFIG_FILE"; then
    sudo sed -i "/server_name $DOMAIN/a include /etc/nginx/snippets/upload-limits.conf;" $CONFIG_FILE
fi

# --- KROK 9: Ostateczny restart Nginx ---
echo ">>> KROK 9: Ostateczny restart Nginx w celu załadowania pancernych nagłówków..."
sudo systemctl restart nginx

# --- KROK 10: Konfiguracja sudoers dla restartu serwera przez aplikację ---
echo ">>> KROK 10: Konfiguracja sudoers dla bezpiecznego restartu..."
SUDOERS_FILE="/etc/sudoers.d/$SERVICE_NAME"
sudo tee $SUDOERS_FILE > /dev/null <<EOF
# Pozwala użytkownikowi aplikacji na restart TYLKO usługi mobywatel
# ZASADA NAJMNIEJSZYCH UPRAWNIEŃ - nic więcej nie jest dozwolone
$PROJECT_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart $SERVICE_NAME
EOF
# Ustaw bezpieczne uprawnienia (wymagane przez sudo)
sudo chmod 440 $SUDOERS_FILE
# Sprawdź poprawność sudoers
sudo visudo -c
echo ">>> Sudoers skonfigurowany - aplikacja może restartować usługę $SERVICE_NAME"

echo
echo "----------------------------------------------------"
echo "✅ WDROŻENIE (v4) ZAKOŃCZONE POMYŚLNIE!"
echo "Twoja strona powinna być dostępna pod adresem: https://$DOMAIN"
echo "Nowe reguły CSP zostały wdrożone."
echo ""
echo "🔄 RESTART SERWERA:"
echo "   - Przez panel admina: przycisk 'Restart serwera'"
echo "   - Przez SSH: sudo systemctl restart $SERVICE_NAME"
echo "----------------------------------------------------"
