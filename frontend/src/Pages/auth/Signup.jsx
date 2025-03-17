import { useState } from "react";
import { BsEnvelope, BsLock, BsPerson } from "react-icons/bs";
import { Link } from "react-router-dom";
import "./Signup.css"; // IMPORTANT: Import CSS like Login!

function SignUp() {
  const [signUpData, setSignUpData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  function handleUserInput(e) {
    const { name, value } = e.target;
    setSignUpData({ ...signUpData, [name]: value });
  }

  function onSignUp(event) {
    event.preventDefault();

    // Basic password match validation
    if (signUpData.password !== signUpData.confirmPassword) {
      alert("Passwords do not match!");
      return;
    }

    console.log("Signing up with:", signUpData);

    // Reset form
    setSignUpData({
      name: "",
      email: "",
      password: "",
      confirmPassword: "",
    });
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

        <button type="submit" className="signup-btn">
          Sign Up
        </button>
      </form>

      <p className="footer-text">
        Already have an account?{" "}
        <Link to="/login">Login</Link> here
      </p>
    </div>
  );
}

export default SignUp;
