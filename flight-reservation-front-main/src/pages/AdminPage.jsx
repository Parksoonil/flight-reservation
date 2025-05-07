// AdminPage.js
import React, { useState, useEffect } from "react";
import apiClient from "../apiClient";
import UserManagement from "../components/UserManagement";
import FlightManagement from "../components/FlightManagement";

const AdminPage = () => {
    const [selectedService, setSelectedService] = useState("users");
    const [users, setUsers] = useState([]);

    useEffect(() => {
        if (selectedService === "users") {
            apiClient
                .get("/api/admin/users")
                .then((response) => {
                    setUsers(response.data);
                })
                .catch((error) => {
                    console.error("Error fetching users:", error);
                });
        }
        // 추가 서비스에 대한 API 호출 분기를 여기에 추가할 수 있습니다.
    }, [selectedService]);

    const handleServiceClick = (service) => {
        setSelectedService(service);
    };

    return (
        <div style={{ display: "flex", height: "100vh", fontFamily: "Arial, sans-serif" }}>
            {/* 왼쪽 메뉴 영역 */}
            <div style={{ width: "250px", backgroundColor: "#f4f4f4", padding: "20px" }}>
                <h2 style={{ borderBottom: "1px solid #ccc", paddingBottom: "10px" }}>서비스</h2>
                <ul style={{ listStyle: "none", padding: 0 }}>
                    <li
                        onClick={() => handleServiceClick("users")}
                        style={{
                            padding: "10px",
                            marginBottom: "5px",
                            backgroundColor: selectedService === "users" ? "#ddd" : "transparent",
                            cursor: "pointer",
                        }}
                    >
                        유저 관리
                    </li>
                    <li
                        onClick={() => handleServiceClick("flight")}
                        style={{
                            padding: "10px",
                            marginBottom: "5px",
                            backgroundColor: selectedService === "flight" ? "#ddd" : "transparent",
                            cursor: "pointer",
                        }}
                    >
                        항공 관리
                    </li>
                    <li
                        onClick={() => handleServiceClick("reservation")}
                        style={{
                            padding: "10px",
                            marginBottom: "5px",
                            backgroundColor: selectedService === "reservation" ? "#ddd" : "transparent",
                            cursor: "pointer",
                        }}
                    >
                        예매 관리
                    </li>
                    {/* 추가 서비스 항목 */}
                </ul>
            </div>

            {/* 오른쪽 콘텐츠 영역 */}
            <div style={{ flex: 1, padding: "20px", overflowY: "auto" }}>
                {selectedService === "users" && (
                    <UserManagement users={users} setUsers={setUsers} />
                )}
                {selectedService === "flight" && <FlightManagement />}
                {selectedService === "reservation" && (
                    <div>
                        <h1>Reservation Management</h1>
                        <p>예약 관리 페이지는 추후 구현 예정입니다.</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AdminPage;
