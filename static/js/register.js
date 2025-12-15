document.addEventListener('DOMContentLoaded', function() {
            // Get all necessary DOM elements once
            const successAlert = document.getElementById("successAlert");
            const errorAlert = document.getElementById("errorAlert");
            const loading = document.getElementById("loading");
            const registerBtn = document.getElementById("registerBtn");
            const registerForm = document.getElementById("registerForm");
            const usernameInput = document.getElementById("username");
            const passwordInput = document.getElementById("password");
            const confirmPasswordInput = document.getElementById("confirm_password");
            const accessKeyInput = document.getElementById("accessKey");

            // Overlay elements
            const fullScreenOverlay = document.getElementById("fullScreenOverlay");
            const overlayTokenDisplay = document.getElementById("overlayTokenDisplay");
            const overlayActualRecoveryToken = document.getElementById("overlayActualRecoveryToken");
            const overlayCopyTokenBtn = document.getElementById("overlayCopyTokenBtn");
            const overlayCountdownMessage = document.getElementById("overlayCountdownMessage");
            const overlayProceedBtn = document.getElementById("overlayProceedBtn");

            function showAlert(message, type) {
                const alertElement = (type === "success" ? successAlert : errorAlert);
                const otherAlert = (type === "success" ? errorAlert : successAlert);

                if (otherAlert) {
                    otherAlert.style.display = "none";
                }

                if (alertElement) {
                    alertElement.textContent = message;
                    alertElement.style.display = "block";
                }

                if (type !== "success" && alertElement) {
                    setTimeout(() => {
                        alertElement.style.display = "none";
                    }, 5000);
                }
            }

            function showLoading(show) {
                if (loading) {
                    loading.style.display = show ? "block" : "none";
                }
                if (registerBtn) {
                    registerBtn.disabled = show;
                    registerBtn.textContent = show ? "Rejestrowanie..." : "Zarejestruj się";
                }
            }

            function showOverlayWithToken(token) {
                if (fullScreenOverlay) {
                    fullScreenOverlay.classList.add("visible"); // Use class to show
                }
                if (overlayActualRecoveryToken) {
                    overlayActualRecoveryToken.textContent = token;
                }
                if (overlayTokenDisplay) {
                    overlayTokenDisplay.setAttribute("data-token", token);
                }

                let countdown = 7;
                if (overlayCountdownMessage) {
                    overlayCountdownMessage.textContent = `Przekierowanie do logowania za ${countdown} sekund...`;
                }

                const interval = setInterval(() => {
                    countdown--;
                    if (overlayCountdownMessage) {
                        overlayCountdownMessage.textContent = `Przekierowanie do logowania za ${countdown} sekund...`;
                    }
                    if (countdown <= 0) {
                        clearInterval(interval);
                        window.location.href = "/login";
                    }
                }, 1000);
            }

            registerForm.addEventListener("submit", async function(e) {
                e.preventDefault();
                showLoading(true);

                const username = usernameInput.value.trim();
                const password = passwordInput.value;
                const confirmPassword = confirmPasswordInput.value;
                const accessKey = accessKeyInput.value.trim();
                const referralCode = document.getElementById("referralCode").value.trim();

                if (password !== confirmPassword) {
                    showAlert('Hasła nie są zgodne', 'error');
                    showLoading(false);
                    return;
                }

                const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

                try {
                    const response = await fetch("/register", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRFToken": csrfToken
                        },
                        body: JSON.stringify({
                            username: username,
                            password: password,
                            access_key: accessKey,
                            referral_code: referralCode
                        })
                    });
                    const data = await response.json();

                    if (data.success) {
                        // Show the full-screen overlay with the token
                        if (data.recovery_token) {
                            showOverlayWithToken(data.recovery_token);
                        } else {
                            // Fallback if for some reason token is not returned
                            showAlert("Rejestracja przebiegła pomyślnie! Możesz się teraz zalogować.", "success");
                            setTimeout(() => { window.location.href = "/login"; }, 5000);
                        }
                        registerForm.reset();
                    } else {
                        showAlert(data.error, "error");
                    }
                } catch (error) {
                    console.error("Error:", error);
                    showAlert("Wystąpił błąd podczas rejestracji. Spróbuj ponownie.", "error");
                } finally {
                    showLoading(false);
                }
            });

            // Real-time validation
            usernameInput.addEventListener("input", function() {
                const username = this.value.trim();
                if (username.length > 0 && username.length < 3) {
                    this.style.borderColor = "#e74c3c";
                } else {
                    this.style.borderColor = "#e1e5e9";
                }
            });

            passwordInput.addEventListener("input", function() {
                const password = this.value;
                if (password.length > 0 && password.length < 6) {
                    this.style.borderColor = "#e74c3c";
                } else {
                    this.style.borderColor = "#e1e5e9";
                }
            });

            // Copy to clipboard functionality for overlay button
            if (overlayCopyTokenBtn) {
                overlayCopyTokenBtn.addEventListener("click", async function() {
                    const token = overlayTokenDisplay.getAttribute("data-token");
                    try {
                        await navigator.clipboard.writeText(token);
                        alert("Token skopiowany do schowka!");
                    } catch (err) {
                        console.error('Failed to copy: ', err);
                        alert('Nie udało się skopiować tokena. Spróbuj ręcznie.');
                    }
                });
            }

            // Proceed button on overlay
            if (overlayProceedBtn) {
                overlayProceedBtn.addEventListener("click", function() {
                    window.location.href = "/login";
                });
            }
        });
