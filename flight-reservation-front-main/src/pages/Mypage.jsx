import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {useDispatch, useSelector} from "react-redux";
import "../style/Mypage.css";
import apiClient from "../apiClient.jsx";
import { jwtDecode } from "jwt-decode";
import {logout} from "../store/authSlice.js";
import ReservationList from "../components/ReservationList.jsx"

function MyPage() {
    const dispatch = useDispatch();
    const { accessToken } = useSelector((state) => state.auth);
    const [user, setUser] = useState(null);
    const navigate = useNavigate();
    const currentUserEmail = useSelector((state) => state.auth.email);

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
    // 회원 탈퇴 버튼 핸들러
    const handleDeleteAccount = async () => {
        // 1. 정말 탈퇴할 것인지 확인
        const isConfirmed = window.confirm("정말로 탈퇴하시겠습니까?");
        if (!isConfirmed) return;

        // 2. 이메일 확인 팝업창 띄우기
        const inputEmail = window.prompt(
            "탈퇴를 진행하기 위해 이메일을 확인합니다. 회원님의 이메일을 입력해주세요."
        );
        if (inputEmail === null || inputEmail.trim() === "") {
            alert("이메일을 입력하지 않으셨습니다. 탈퇴가 취소됩니다.");
            return;
        }

        // 3. 입력받은 이메일과 현재 사용자의 이메일 비교 (대소문자 구분 없이 비교)
        if (inputEmail.trim().toLowerCase() !== currentUserEmail.toLowerCase()) {
            alert("입력하신 이메일이 올바르지 않습니다. 탈퇴가 취소되었습니다.");
            return;
        }

        // 4. 이메일 검증이 완료되면 탈퇴 로직 실행 (user.id를 통한 API 호출)
        try {
            // 회원 탈퇴 API 호출 (소프트 딜리트 또는 실제 삭제)
            await apiClient.delete(`/api/users/${user.id}`);
            alert("회원 탈퇴 처리가 완료되었습니다.");

            // 탈퇴 후 백엔드 로그아웃 엔드포인트 호출 (HttpOnly refresh token 만료)
            await apiClient.post("/api/users/logout");

            // 클라이언트 측 Redux 로그아웃 처리 (accessToken 등 제거)
            dispatch(logout());

            // 탈퇴 후 로그인 페이지로 이동 (또는 원하는 다른 페이지로 이동)
            navigate("/login");
        } catch (error) {
            console.error("회원 탈퇴에 실패했습니다.", error);
            alert("회원 탈퇴에 실패했습니다. 다시 시도해주세요.");
        }
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
                    <button onClick={handleDeleteAccount} className="edit-button">
                        회원 탈퇴
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
                    <ReservationList userId={user.id} />
                </>
            ) : (
                <p>Loading...</p>
            )}
        </div>
    );
}

export default MyPage;