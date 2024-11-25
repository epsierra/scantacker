import { useState } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router";
import HomeScreen from "./screens/HomeScreen";
import LoginScreen from "./screens/LoginScreen";
import RegisterScreen from "./screens/RegisterScreen";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route index element={<HomeScreen />} />
        <Route path="login" element={<LoginScreen />} />
        <Route path="register" element={<RegisterScreen />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
