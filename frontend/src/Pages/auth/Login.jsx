import { useState } from "react";
import { BsEnvelope, BsLock } from "react-icons/bs";
import { Link } from "react-router-dom";
import axios from "axios";
import "./Login.css";

function LogIn() {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [error, setError] = useState("");

  function handleUserInput(e) {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  }

  // Login User
  async function handleLogin(event) {
    event.preventDefault();
    try {
      const res = await axios.post("http://localhost:8000/login", {
        email: formData.email,
        password: formData.password,
      });

      if (res.data && res.data.token) {
        const authToken = res.data.token;
        setToken(authToken);
        
        localStorage.setItem("token", authToken);

        // Request OTP after successful login
        const otpRes = await axios.post(
          "http://localhost:8000/request-otp1",
          { email: formData.email },
          { headers: { Authorization: `Bearer ${authToken}` } }
        );

        if (otpRes.data) {
          const userOtp = prompt("Enter the OTP sent to your email:");

          // Verify OTP
          const verifyRes = await axios.post(
            "http://localhost:8000/verify-otp1",
            { email: formData.email, otp: userOtp },
            { headers: { Authorization: `Bearer ${authToken}` } }
          );
          if (verifyRes.data) {
            localStorage.setItem("email", formData.email);
            alert("OTP verified successfully! You are logged in.");
          } else {
            alert("Invalid OTP! Please try again.");
          }
        }
      } else {
        setError("Invalid credentials!");
      }
    } catch (err) {
      setError("Login failed! Please check your credentials.");
    }
  }

  return (
    <div className="login-container">
      <form onSubmit={handleLogin} className="login-form">
        <div>
          <h1>Log In</h1>
          <p>Please fill this form to log in</p>
        </div>
        <hr />

        <div className="input-group">
          <label htmlFor="email">
            <BsEnvelope />
          </label>
          <input
            type="email"
            name="email"
            id="email"
            placeholder="Enter Email"
            value={formData.email}
            onChange={handleUserInput}
            required
          />
        </div>

        <div className="input-group">
          <label htmlFor="password">
            <BsLock />
          </label>
          <input
            type="password"
            name="password"
            id="password"
            placeholder="Enter Password"
            value={formData.password}
            onChange={handleUserInput}
            required
          />
        </div>

        {error && <p className="error-text">{error}</p>}

        <button type="submit" className="login-btn">
          Log In
        </button>
      </form>

      <p className="footer-text">
        Don't have an account?{" "}
        <Link to={"/signup"}>
          Signup
        </Link>{" "}
        here
      </p>
    </div>
  );
}

export default LogIn;
