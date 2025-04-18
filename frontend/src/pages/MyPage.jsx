import {useEffect, useState} from "react";
import apiClient from "../apiClient.jsx";

function MyPage() {
    const [users, setUsers] = useState([]);
    useEffect(() => {
        apiClient.get("/api/users")
            .then(response => setUsers(response.data))
            .catch(error => console.error("데이터 로드 실패:", error));
    }, []);

    return (
        <div>
            <h1>User List</h1>
            ) : users.length === 0 ? (
                <p>Loading...</p>
            ) : (
                <ul>
                    {users.map((user) => (
                        <li key={user.id}>
                            {user.userFirstName} {user.userLastName} - {user.email}
                        </li>
                    ))}
                </ul>
            )
        </div>
    );
}

export default MyPage;