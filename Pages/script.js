const API_URL = "http://localhost:8000";

        // Ensure functions are defined before use
        window.requestOTP = function requestOTP(type) {
            const email = type === "register"
                ? document.getElementById("regEmail").value
                : prompt("Enter your registered email:");

            if (!email) {
                alert("Email is required.");
                return;
            }

            fetch(`${API_URL}/request-otp?email=${encodeURIComponent(email)}`)
                .then(response => response.json())
                .then(data => {
                    alert(data.message || "OTP sent successfully!");
                })
                .catch(error => {
                    alert("Error sending OTP. Try again.");
                    console.error(error);
                });
        };

        window.registerUser = function registerUser() {
            const username = document.getElementById("regUsername").value;
            const email = document.getElementById("regEmail").value;
            const password = document.getElementById("regPassword").value;

            if (!username || !email || !password) {
                alert("All fields are required.");
                return;
            }

            const otp = prompt("Enter the OTP sent to your email:");

            fetch(`${API_URL}/register?otp=${otp}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, email, password })
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message || "Registration successful!");
            })
            .catch(error => {
                alert("Error registering. Try again.");
                console.error(error);
            });
        };

        window.loginUser = function loginUser() {
            const username = document.getElementById("loginUsername").value;
            const password = document.getElementById("loginPassword").value;
            requestOTP('login')

            if (!username || !password) {
                alert("All fields are required.");
                return;
            }

            fetch(`${API_URL}/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert(data.error);
                } else {
                    const otp = prompt("Enter the OTP sent to your email:");
                    verifyOTP(otp, username);
                }
            })
            .catch(error => {
                alert("Error logging in. Try again.");
                console.error(error);
            });
        };

        window.verifyOTP = function verifyOTP(otp, username) {
            fetch(`${API_URL}/verify-otp?email=${username}&otp=${otp}`)
                .then(response => response.json())
                .then(data => {
                    alert(data.message || "Login successful!");
                })
                .catch(error => {
                    alert("Error verifying OTP. Try again.");
                    console.error(error);
                });
        };