import { useState } from "react";
import { BsEnvelope, BsLock } from "react-icons/bs";
import { Link } from "react-router-dom";
import "./Login.css";

function LogIn() {
  const [logInData, setLogInData] = useState({
    email: "",
    password: "",
  });

  function handleUserInput(e) {
    const { name, value } = e.target;
    setLogInData({ ...logInData, [name]: value });
  }

  function onLogin(event) {
    event.preventDefault();
    console.log("Logging in with:", logInData);

    // Reset form
    setLogInData({
      email: "",
      password: "",
    });
  }

  return (
<div className="login-container">
  <form onSubmit={onLogin} className="login-form">
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
        value={logInData.email}
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
        value={logInData.password}
        onChange={handleUserInput}
        required
      />
    </div>

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
