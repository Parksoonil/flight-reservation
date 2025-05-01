import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";
import "../style/Mypage.css";
import apiClient from "../apiClient.jsx";
import {jwtDecode} from "jwt-decode";

function MyPage() {
    const { accessToken } = useSelector((state) => state.auth);
    const [user, setUser] = useState(null);
    const [reservations, setReservations] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        // accessToken이 없으면 로그인 페이지로 이동합니다.
        if (!accessToken) {
            navigate("/login");
            return;
        }

        // 토큰을 디코드하여 userid 추출 (jwt 토큰이 올바른 형식이어야 함)
        let userid;
        try {
            // 예를 들어, JWT 토큰 발급 시 claims에 "userid"를 포함시켰다면
            const decoded = jwtDecode(accessToken);
            userid = decoded.userid;
        } catch (error) {
            console.error("토큰 디코딩 실패:", error);
            navigate("/login");
            return;
        }

        if (!userid) {
            navigate("/login");
            return;
        }

        // 즉시 실행하는 async 함수를 사용하여 사용자 및 예약 정보를 가져옵니다.
        (async () => {
            try {
                // 사용자 정보를 userid 기준으로 API 호출
                const { data: userDataRaw } = await apiClient.get(`api/users?userId=${userid}`);
                const userData = Array.isArray(userDataRaw) ? userDataRaw[0] : userDataRaw;
                if (userData) {
                    setUser(userData);

                    // 예약 내역도 userid 기준으로 API 호출
                    const { data: reservationsData } = await apiClient.get(`api/reservations?userId=${userid}`);
                    setReservations(reservationsData);
                }
            } catch (error) {
                console.error("사용자 정보 또는 예약을 불러오는 데 실패했습니다.", error);
            }
        })();
    }, [accessToken, navigate]);

    return (
        <div className="my-page">
            {user ? (
                <>
                    <h2>마이 페이지</h2>
                    <p>
                        <strong>이메일:</strong> {user.email}
                    </p>
                    <p>
                        <strong>이름:</strong> {user.userFirstName} {user.userLastName}
                    </p>
                    <p>
                        <strong>전화번호:</strong> {user.phone}
                    </p>
                    <p>
                        <strong>생년월일:</strong>{" "}
                        {user.birthday ? new Date(user.birthday).toLocaleDateString() : "N/A"}
                    </p>
                    <p>
                        <strong>주소:</strong> {user.address}
                    </p>

                    <h3>예약 목록</h3>
                    {reservations.length > 0 ? (
                        <div className="reservation-list">
                            {reservations.map((reservation) => (
                                <div className="reservation-card" key={reservation.id}>
                                    <h4>예약 번호: {reservation.id}</h4>
                                    <p>
                                        <strong>항공편:</strong> {reservation.flight.aircraftType}
                                    </p>
                                    <p>
                                        <strong>출발지 / 도착지:</strong> {reservation.flight.departureName} / {reservation.flight.arrivalName}
                                    </p>
                                    <p>
                                        <strong>출발 날짜:</strong> {reservation.flight.departureTime.split("T")[0]}
                                    </p>
                                    <p>
                                        <strong>좌석 번호:</strong> {reservation.selectedSeats.join(", ")}
                                    </p>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p>현재 예약이 없습니다.</p>
                    )}
                </>
            ) : (
                <p>Loading...</p>
            )}
        </div>
    );
}

export default MyPage;
