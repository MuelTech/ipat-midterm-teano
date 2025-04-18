import { useState } from "react";
import axios from "axios";
import { TextField, Button, Container, Typography } from "@mui/material";
import { useNavigate } from "react-router-dom";

const Login = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const navigate = useNavigate();

    const handleLogin = async () => {
        if (!username || !password) {
            alert("Please fill in all fields");
            return;
        }

        try {
            const response = await axios.post(
                "http://localhost:5000/login",
                { username, password },
                { headers: { "Content-Type": "application/json" } }
            );

            // Store token, username, and role in localStorage
            localStorage.setItem("token", response.data.token);
            localStorage.setItem("username", response.data.username); // Store username
            localStorage.setItem("role", response.data.role); // Store role

            alert("Login successful!");
            // Redirect to dashboard
            navigate("/dashboard");
        } catch (error) {
            alert(error.response?.data?.message || "Invalid credentials");
        }
    };


    return (
        <Container maxWidth="xs">
            <Typography variant="h4">Login</Typography>
            <TextField label="Username" fullWidth margin="normal" value={username} onChange={(e) => setUsername(e.target.value)} />
            <TextField label="Password" type="password" fullWidth margin="normal" value={password} onChange={(e) => setPassword(e.target.value)} />
            <Button variant="contained" color="primary" fullWidth onClick={handleLogin}>
                Login
            </Button>
        </Container>
    );
};

export default Login;
