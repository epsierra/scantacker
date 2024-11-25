import { useNavigate } from "react-router";

function LoginScreen() {
  let navigate = useNavigate();
  const handleLogin = () => {
    navigate("/");
  };

  return (
    <div id="App">
      <h2>Login</h2>
      <button className="btn" onClick={handleLogin}>
        Login
      </button>
    </div>
  );
}

export default LoginScreen;
