import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Container, Typography, Button } from "@mui/material";

const Dashboard1 = () => {
    const navigate = useNavigate();
    const [user, setUser] = useState("");
    const [userRole, setRole] = useState("");

    useEffect(() => {
        // Retrieve the user and role from localStorage
        const storedUser = localStorage.getItem("username");
        const storedRole = localStorage.getItem("role");

        console.log("Stored User:", storedUser); // Debugging log
        console.log("Stored Role:", storedRole); // Debugging log

        if (storedUser && storedRole) {
            setUser(storedUser);
            setRole(storedRole);

            // If the user is not a staff member, redirect them
            if (storedRole !== "Staff") {
                console.log("Not Staff, redirecting to certificate..."); // Debugging log
                navigate("/certificate");
            }
        } else {
            console.log("No user or role found, redirecting to login..."); // Debugging log
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
                    // Clear localStorage and redirect to login
                    localStorage.removeItem("token");
                    localStorage.removeItem("username");
                    localStorage.removeItem("role");
                    navigate("/login");
                }}
            >
                Logout
            </Button>
        </Container>
    );
};

export default Dashboard1;
