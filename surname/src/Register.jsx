import { useState } from "react";
import axios from "axios";
import { TextField, Button, Container, Typography, Stack } from "@mui/material";
import { useNavigate } from "react-router-dom";

const Register = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [role, setRole] = useState("");
    const navigate = useNavigate();

    const handleRegister = async () => {
        if (!username || !password) {
            alert("please fill in all fields");
            return;
        }

        try {
            const response = await axios.post("http://localhost:5000/register", { username, password, role }, { headers: { "Content-Type": "application/json" } });
            alert(response.data.message);
            navigate("/login");
        } catch (error) {
            alert(error.response?.data?.message || "Registration Failed");
        }
    };

    return (
        <Container maxWidth="sm">
            <Typography variant="h4" gutterBottom>
                Register
            </Typography>

            <Stack spacing={2}>
                <TextField
                    label="Username"
                    fullWidth
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                />
                <TextField
                    label="Password"
                    type="password"
                    fullWidth
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                />
                <TextField
                    label="Role/StudentID"
                    type="role-studentid"
                    fullWidth
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                />

                <Button
                    variant="contained"
                    color="primary"
                    fullWidth
                    onClick={handleRegister}
                >
                    Create Account
                </Button>

                <Button
                    variant="text"
                    color="secondary"
                    fullWidth
                    onClick={() => navigate("/login")}
                >
                    Already have an account? Login
                </Button>
            </Stack>
        </Container>
    );
};


export default Register;