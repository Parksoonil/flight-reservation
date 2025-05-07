import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import apiClient from "../apiClient.jsx";
import { jwtDecode } from "jwt-decode";
import "../style/EditProfile.css";

function EditProfile() {
    const { accessToken } = useSelector((state) => state.auth);
    const navigate = useNavigate();

    // 초기 사용자 상태 (이메일은 수정 불가하므로 form에 미리 채워놓습니다.)
    const [user, setUser] = useState({
        id: null,
        email: "",
        userFirstName: "",
        userLastName: "",
        phone: "",
        birthday: "", // ISO 형식(YYYY-MM-DD) 등으로 변경하여 사용
        address: "",
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        if (!accessToken) {
            navigate("/login");
            return;
        }

        // JWT 토큰에서 사용자 ID 추출
        let userId;
        try {
            const decoded = jwtDecode(accessToken);
            userId = decoded.userid; // 토큰에 userid 필드가 있다고 가정합니다.
        } catch (err) {
            console.error("토큰 디코딩 실패:", err);
            navigate("/login");
            return;
        }

        async function fetchUserData() {
            try {
                // GET 요청: 사용자 정보를 조회합니다.
                const { data: userData } = await apiClient.get(`api/users/id/${userId}`);
                setUser({
                    id: userData.id, // 업데이트 시 id가 필요합니다.
                    email: userData.email,
                    userFirstName: userData.userFirstName,
                    userLastName: userData.userLastName,
                    phone: userData.phone,
                    birthday: userData.birthday, // 서버에서 ISO 또는 Date형태로 반환한다면 후처리 필요할 수 있음.
                    address: userData.address,
                });
            } catch (e) {
                console.error("사용자 정보를 불러오는데 실패했습니다.", e);
                setError("사용자 정보를 불러오는데 실패했습니다.");
            } finally {
                setLoading(false);
            }
        }
        fetchUserData();
    }, [accessToken, navigate]);

    // 입력 폼의 값이 변경될 때 상태 업데이트
    const handleChange = (e) => {
        const { name, value } = e.target;
        if (name === "phone") {
            // 숫자가 아닌 문자는 제거하고 최대 11자리로 제한합니다.
            let numericValue = value.replace(/\D/g, "");
            numericValue = numericValue.slice(0, 11);
            setUser((prev) => ({
                ...prev,
                [name]: numericValue,
            }));
        } else {
            setUser((prev) => ({
                ...prev,
                [name]: value,
            }));
        }
    };

    // 폼 제출 시 수정된 정보를 PUT 엔드포인트를 통해 전송합니다.
    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            console.log(user.id);
            console.log(user);
            await apiClient.put(`api/users/${user.id}`, user);
            alert("내정보가 성공적으로 업데이트되었습니다.");
            navigate("/mypage");
        } catch (e) {
            console.error("내정보 업데이트 오류", e);
            setError("내정보 업데이트 중 문제가 발생했습니다.");
        }
    };

    if (loading) {
        return <div>Loading...</div>;
    }

    return (
        <div className="edit-profile">
            <h2>내정보 수정</h2>
            {error && <p className="error-message">{error}</p>}
            <form onSubmit={handleSubmit} className="edit-profile-form">
                <div className="form-group">
                    <label htmlFor="email">이메일</label>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        value={user.email}
                        disabled
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="userFirstName">이름</label>
                    <input
                        type="text"
                        id="userFirstName"
                        name="userFirstName"
                        value={user.userFirstName}
                        onChange={handleChange}
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="userLastName">성</label>
                    <input
                        type="text"
                        id="userLastName"
                        name="userLastName"
                        value={user.userLastName}
                        onChange={handleChange}
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="phone">전화번호</label>
                    <input
                        type="tel"
                        id="phone"
                        name="phone"
                        value={user.phone}
                        onChange={handleChange}
                        maxLength="11"
                        pattern="\d{11}"
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="birthday">생년월일</label>
                    <input
                        type="date"
                        id="birthday"
                        name="birthday"
                        value={
                            user.birthday
                                ? new Date(user.birthday).toISOString().substring(0, 10)
                                : ""
                        }
                        onChange={handleChange}
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="address">주소</label>
                    <input
                        type="text"
                        id="address"
                        name="address"
                        value={user.address}
                        onChange={handleChange}
                    />
                </div>
                <div className="button-group">
                    <button type="submit">저장</button>
                    <button type="button" onClick={() => navigate("/mypage")}>
                        취소
                    </button>
                </div>
            </form>
        </div>
    );
}

export default EditProfile;
