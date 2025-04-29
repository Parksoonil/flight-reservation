import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import apiClient from "../apiClient.jsx";
import "../style/Login.css";
import { login } from "../store/authSlice"; // Redux 로그인 액션 (예시)

function Login() {
    const navigate = useNavigate();
    const dispatch = useDispatch();

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            // withCredentials 옵션을 활성화하여 HTTPOnly 쿠키가 서버의 Set-Cookie 헤더를 통해 전달되도록 합니다.
            const res = await apiClient.post(
                "api/users/login",
                { email, password },
                { withCredentials: true }
            );
            // HTTPOnly 쿠키에 액세스 토큰이 이미 설정되었으므로, 응답에는 사용자 정보만 포함됩니다.
            const { user } = res.data;
            // Redux 로그인 액션을 dispatch하여 사용자 정보를 저장합니다.
            dispatch(login({ email: user.email, user }));

            alert("로그인 성공");
            navigate("/");
        } catch (err) {
            console.error("로그인 오류", err);
            setError("이메일 또는 비밀번호를 확인해 주세요");
        }
    };

    return (
        <div className="login-page">
            <h2>로그인</h2>
            <form onSubmit={handleLogin} className="login-form">
                <div>
                    <label htmlFor="email">이메일</label>
                    <input
                        type="text"
                        id="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
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
                <button type="submit">로그인</button>
                {error && <p className="error-message">{error}</p>}
            </form>
            <p onClick={() => navigate("/signup")} className="signup-link">
                계정이 없으신가요? 회원가입
            </p>
        </div>
    );
}

export default Login;