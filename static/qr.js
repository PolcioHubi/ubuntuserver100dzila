const totalSeconds = 180;
let currentSeconds = totalSeconds;

const bar = document.querySelector('.progress-bar');
const timerText = document.getElementById('timer-text');

const interval = setInterval(() => {
currentSeconds--;

const minutes = Math.floor(currentSeconds / 60);
const seconds = currentSeconds % 60;
timerText.textContent = `Kod wygaśnie za: ${minutes} min ${seconds} sek.`;

const widthPercent = (currentSeconds / totalSeconds) * 100;
bar.style.width = `${widthPercent}%`;

if (currentSeconds <= 0) {
  clearInterval(interval);
  timerText.textContent = "Kod wygasł.";
  bar.style.width = "0%";
}
}, 1000);

function generateRandomCode(length = 6) {
return Math.floor(100000 + Math.random() * 900000).toString();
}

// Generate QR code using local canvas (fallback if external API fails)
function generateQRCodeLocally(text) {
    const canvas = document.createElement('canvas');
    const size = 200;
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');
    
    // Simple QR-like pattern (visual placeholder)
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#fff';
    ctx.fillRect(10, 10, size - 20, size - 20);
    ctx.fillStyle = '#000';
    ctx.font = 'bold 24px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    
    // Draw code in center
    const lines = text.match(/.{1,3}/g) || [text];
    lines.forEach((line, i) => {
        ctx.fillText(line, size / 2, size / 2 + (i - lines.length / 2 + 0.5) * 30);
    });
    
    return canvas.toDataURL();
}

function updateQRCode() {
const code = generateRandomCode();
const qrImage = document.getElementById('qr-image');
const codeText = document.getElementById('qr-code-text');

// Primary method: External API
const apiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${code}`;

// Set text immediately
codeText.textContent = code;

// Try loading from external API with error handling
qrImage.onerror = function() {
    console.warn('Failed to load QR from external API, using local generation');
    qrImage.src = generateQRCodeLocally(code);
    qrImage.onerror = null; // Prevent infinite loop
};

// Add loading state
qrImage.style.opacity = '0.5';
qrImage.onload = function() {
    qrImage.style.opacity = '1';
    console.log('QR code loaded successfully');
};

// Set source
qrImage.src = apiUrl;

// Timeout fallback (if image doesn't load within 3 seconds)
setTimeout(() => {
    if (!qrImage.complete || qrImage.naturalWidth === 0) {
        console.warn('QR API timeout, using local generation');
        qrImage.src = generateQRCodeLocally(code);
    }
}, 3000);
}

updateQRCode();
