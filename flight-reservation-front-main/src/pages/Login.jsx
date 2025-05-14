import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import apiClient from "../apiClient.jsx";
import "../style/Login.css";
import { login } from "../store/authSlice";
import {jwtDecode} from "jwt-decode";

function Login() {
    const navigate = useNavigate();
    const dispatch = useDispatch();

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            const res = await apiClient.post("api/users/login", { email, password });
            // 백엔드가 로그인 성공 시 accessToken만 반환합니다.
            const { accessToken } = res.data;

            // JWT 토큰 디코딩
            const decoded = jwtDecode(accessToken);
            const userEmail = decoded.sub; // 토큰의 subject에 저장된 이메일

            // Redux에 로그인 정보 저장
            dispatch(login({ email: userEmail, accessToken, user: decoded }));

            alert("로그인 성공");
            navigate("/");
        } catch (err) {
            console.error("로그인 오류", err);

            // 백엔드에서 삭제 요청된 사용자인 경우 403 상태와 지정한 메시지를 반환합니다.
            if (err.response && err.response.status === 403 && err.response.data === "삭제 요청된 사용자입니다.") {
                alert("삭제 요청된 사용자입니다. 관리자에게 문의해 주세요.");
                return;
            }
            // 그 외 인증 실패의 경우 에러 메시지 출력
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
            <p onClick={() => navigate("/findAccount")} className="signup-link">
                아이디/비밀번호 찾기
            </p>
            <p onClick={() => navigate("/signup")} className="signup-link">
                계정이 없으신가요? 회원가입
            </p>
        </div>
    );
}

export default Login;
