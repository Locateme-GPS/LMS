import React from "react";
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Login from './Pages/auth/Login';   // Correct
import Signup from './Pages/auth/Signup'; // FIXED: Should be Signup, not Login

const App = () => {
    return (
        <Router>
            <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/signup" element={<Signup />} />
                <Route path="/" element={
                    <div>
                        <h1>Hello, world</h1>
                        <p>Welcome to React</p>
                    </div>
                } />
            </Routes>
        </Router>
    );
};

export default App;
