import { useState } from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../apiClient.jsx";
import "../style/Signup.css";

function Signup() {
    const navigate = useNavigate();

    // 기존의 username 대신 email 사용
    const [email, setEmail] = useState("");
    // 이름을 firstName과 lastName으로 분리 (백엔드의 user_first_name, user_last_name에 대응)
    const [firstName, setFirstName] = useState("");
    const [lastName, setLastName] = useState("");
    // 새로 추가된 전화번호 필드 (백엔드의 phone에 대응)
    const [phone, setPhone] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState(null);

    const handleSignup = async (e) => {
        e.preventDefault();

        try {
            // 백엔드 UserEntity 에 맞춰서 데이터를 전송합니다.
            const response = await apiClient.post("api/users", {
                email,
                password,
                userFirstName: firstName,
                userLastName: lastName,
                phone,
            });

            if (response.data) {
                // 응답 데이터가 있다면 localStorage에 저장 (또는 추후 Redux로 관리)
                localStorage.setItem("user", JSON.stringify(response.data));
                navigate("/");
            }
        } catch (err) {
            console.error("회원가입 오류", err);
            setError("회원가입 중 오류가 발생했습니다. 나중에 다시 시도해주세요.");
        }
    };

    return (
        <div className="signup-page">
            <h2>회원가입</h2>
            <form onSubmit={handleSignup} className="signup-form">
                <div>
                    <label htmlFor="email">이메일</label>
                    <input
                        type="email"
                        id="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                    />
                </div>
                <div>
                    <label htmlFor="firstName">이름</label>
                    <input
                        type="text"
                        id="firstName"
                        value={firstName}
                        onChange={(e) => setFirstName(e.target.value)}
                        required
                    />
                </div>
                <div>
                    <label htmlFor="lastName">성</label>
                    <input
                        type="text"
                        id="lastName"
                        value={lastName}
                        onChange={(e) => setLastName(e.target.value)}
                        required
                    />
                </div>
                <div>
                    <label htmlFor="phone">전화번호</label>
                    <input
                        type="tel"
                        id="phone"
                        value={phone}
                        onChange={(e) => setPhone(e.target.value)}
                        required
                    />
                </div>
                <div>
                    <label htmlFor="password">비밀번호</label>
                    <input
                        type="password"
                        id="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                    />
                </div>
                <button type="submit">회원가입</button>
                {error && <p className="error-message">{error}</p>}
                <p onClick={() => navigate("/login")} className="login-link">
                    이미 계정이 있으신가요? 로그인
                </p>
            </form>
        </div>
    );
}

export default Signup;
