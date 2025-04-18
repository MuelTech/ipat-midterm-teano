import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Container, Typography, Button } from "@mui/material";

const Dashboard = () => {
    const navigate = useNavigate();
    const [user, setUser] = useState("");
    const [userRole, setRole] = useState("");

    useEffect(() => {
        // Retrieve username and role from localStorage
        const storedUser = localStorage.getItem("username");
        const storedRole = localStorage.getItem("role");

        if (storedUser && storedRole) {
            setUser(storedUser);
            setRole(storedRole);

            // If role is not Admin, redirect to the staff page
            if (storedRole !== "Admin") {
                navigate("/staff");
            }
        } else {
            // If no user or role found in localStorage, redirect to login
            console.log("No user or role found, redirecting to login...");
            navigate("/login");
        }
    }, [navigate]);

    return (
        <Container>
            <Typography variant="h4">
                Welcome {userRole} {user}
            </Typography>

            <Button
                variant="contained"
                color="secondary"
                onClick={() => {
                    // Remove user data from localStorage and redirect to login page
                    localStorage.removeItem("token");
                    localStorage.removeItem("username");
                    localStorage.removeItem("role"); // Ensure role is also removed
                    navigate("/login");
                }}
            >
                Logout
            </Button>
        </Container>
    );
};

export default Dashboard;

