import { useState } from "react";
import { BsEnvelope, BsLock, BsPerson } from "react-icons/bs";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import "./Signup.css";

function SignUp() {
  const [signUpData, setSignUpData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const [error, setError] = useState("");
  const navigate = useNavigate();

  function handleUserInput(e) {
    const { name, value } = e.target;
    setSignUpData({ ...signUpData, [name]: value });
  }

  async function onSignUp(event) {
    event.preventDefault();

    if (signUpData.password !== signUpData.confirmPassword) {
      alert("Passwords do not match!");
      return;
    }

    try {
      // Step 1: Request OTP
      const otpRes = await axios.post("http://localhost:8000/request-otp1", {
        email: signUpData.email,
      });

      if (otpRes.data) {
        alert("OTP sent to your email. Please check your inbox.");

        // Step 2: Prompt user for OTP
        const otp = window.prompt("Enter OTP sent to your email:");

        if (otp) {
          // Step 3: Verify OTP
          const verifyRes = await axios.post("http://localhost:8000/verify-otp1", {
            email: signUpData.email,
            otp: otp,
          });

          if (verifyRes.data) {
            // Step 4: Register the user after OTP verification
            const registerRes = await axios.post("http://localhost:8000/register", {
              username: signUpData.name,
              email: signUpData.email,
              password: signUpData.password,
            });

            if (registerRes.data.success) {
              alert("Registration successful! Redirecting to login...");
              navigate("/login");
            } else {
              alert(registerRes.data.message || "Registration failed. Please try again.");
            }
          } else {
            alert("Invalid OTP! Please try again.");
          }
        } else {
          alert("OTP verification canceled.");
        }
      } else {
        setError("Failed to send OTP. Try again later.");
      }
    } catch (err) {
      setError("Something went wrong. Please try again.");
    }
  }

  return (
    <div className="signup-container">
      <form onSubmit={onSignUp} className="signup-form">
        <div>
          <h1>Sign Up</h1>
          <p>Please fill this form to create an account</p>
        </div>
        <hr />

        <div className="input-group">
          <label htmlFor="name">
            <BsPerson />
          </label>
          <input
            type="text"
            name="name"
            id="name"
            placeholder="Enter Name"
            value={signUpData.name}
            onChange={handleUserInput}
            required
          />
        </div>

        <div className="input-group">
          <label htmlFor="email">
            <BsEnvelope />
          </label>
          <input
            type="email"
            name="email"
            id="email"
            placeholder="Enter Email"
            value={signUpData.email}
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
            value={signUpData.password}
            onChange={handleUserInput}
            required
          />
        </div>

        <div className="input-group">
          <label htmlFor="confirmPassword">
            <BsLock />
          </label>
          <input
            type="password"
            name="confirmPassword"
            id="confirmPassword"
            placeholder="Confirm Password"
            value={signUpData.confirmPassword}
            onChange={handleUserInput}
            required
          />
        </div>

        {error && <p className="error-message">{error}</p>}

        <button type="submit" className="signup-btn">
          Sign Up
        </button>
      </form>

      <p className="footer-text">
        Already have an account? <Link to="/login">Login</Link> here
      </p>
    </div>
  );
}

export default SignUp;
