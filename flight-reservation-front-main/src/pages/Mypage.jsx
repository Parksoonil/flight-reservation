import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";
import "../style/Mypage.css";
import apiClient from "../apiClient.jsx";

function MyPage() {
    const navigate = useNavigate();
    const { email } = useSelector((state) => state.auth); // Redux의 auth slice에서 email을 가져옵니다.
    const [user, setUser] = useState(null);
    const [reservations, setReservations] = useState([]);

    useEffect(() => {
        // 로그인되어 있지 않다면 로그인 페이지로 이동합니다.
        if (!email) {
            navigate("/login");
        } else {
            const fetchUserAndReservations = async () => {
                try {
                    // 이메일을 기준으로 사용자 정보 API 호출
                    const userResponse = await apiClient.get(`api/users?email=${email}`);
                    let userData = null;
                    if (Array.isArray(userResponse.data)) {
                        // 만약 반환 값이 배열이면 첫 번째 항목을 사용합니다.
                        userData = userResponse.data[0];
                    } else {
                        userData = userResponse.data;
                    }
                    if (userData) {
                        setUser(userData);

                        // 사용자 id를 기준으로 예약 내역 API 호출
                        const reservationsResponse = await apiClient.get(`api/reservations?userId=${userData.id}`);
                        setReservations(reservationsResponse.data);
                    }
                } catch (error) {
                    console.error("사용자 정보 또는 예약을 불러오는 데 실패했습니다.", error);
                }
            };

            fetchUserAndReservations();
        }
    }, [email, navigate]);

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
