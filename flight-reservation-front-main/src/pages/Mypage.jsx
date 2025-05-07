import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";
import "../style/Mypage.css";
import apiClient from "../apiClient.jsx";
import { jwtDecode } from "jwt-decode";

function MyPage() {
    const { accessToken } = useSelector((state) => state.auth);
    const [user, setUser] = useState(null);
    const [reservations, setReservations] = useState([]);
    const navigate = useNavigate();

    // 전화번호 형식을 "010-2222-3333"으로 변경하는 헬퍼 함수
    const formatPhone = (phone) => {
        if (!phone || phone.length < 10) return phone;
        return `${phone.slice(0, 3)}-${phone.slice(3, 7)}-${phone.slice(7)}`;
    };

    // 생년월일을 "1970년 1월 9일" 형식으로 변경하는 헬퍼 함수
    const formatBirthday = (birthday) => {
        const date = new Date(birthday);
        if (isNaN(date)) return birthday;
        const year = date.getFullYear();
        const month = date.getMonth() + 1;
        const day = date.getDate();
        return `${year}년 ${month}월 ${day}일`;
    };

    useEffect(() => {
        // accessToken이 없으면 로그인 페이지로 이동합니다.
        if (!accessToken) {
            navigate("/login");
            return;
        }

        // 토큰을 디코드하여 userid 추출 (jwt 토큰이 올바른 형식이어야 함)
        let userid;
        try {
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
                const { data: userDataRaw } = await apiClient.get(`api/users/id/${userid}`);
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

    // 내정보 수정 페이지로 이동하는 버튼 핸들러
    const handleEditProfile = () => {
        navigate("/editProfile");
    };

    return (
        <div className="my-page">
            {user ? (
                <>
                    <h2>마이 페이지</h2>
                    {/* 내정보 수정 버튼 추가 */}
                    <button onClick={handleEditProfile} className="edit-button">
                        내정보 수정
                    </button>
                    <p>
                        <strong>이메일:</strong> {user.email}
                    </p>
                    <p>
                        <strong>이름:</strong> {user.userFirstName} {user.userLastName}
                    </p>
                    <p>
                        <strong>전화번호:</strong> {formatPhone(user.phone)}
                    </p>
                    <p>
                        <strong>생년월일:</strong>{" "}
                        {user.birthday ? formatBirthday(user.birthday) : "N/A"}
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
                                        <strong>출발지 / 도착지:</strong> {reservation.flight.departureName} /{" "}
                                        {reservation.flight.arrivalName}
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
