import { useState } from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../apiClient.jsx";
import "../style/Signup.css";

function Signup() {
    const navigate = useNavigate();

    // 상태 변수 선언 (이메일, 이름, 전화번호, 비밀번호 등)
    const [email, setEmail] = useState("");
    const [firstName, setFirstName] = useState("");
    const [lastName, setLastName] = useState("");
    const [phone, setPhone] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    // 이메일 인증 관련 상태 변수
    const [verificationCode, setVerificationCode] = useState("");
    const [isEmailVerified, setIsEmailVerified] = useState(false);
    const [verificationSent, setVerificationSent] = useState(false);
    const [verificationMessage, setVerificationMessage] = useState("");

    const [error, setError] = useState(null);

    // 이메일 인증번호 발송 요청
    const handleSendVerificationCode = async () => {
        setError(null);
        if (!email) {
            setError("먼저 이메일을 입력해주세요.");
            return;
        }

        try {
            // 백엔드에서 이메일로 인증번호를 발송하는 API 호출
            await apiClient.post("api/users/mail/send-verification", { email });
            setVerificationSent(true);
            setVerificationMessage("인증번호가 이메일로 전송되었습니다. 이메일을 확인해주세요.");
        } catch (err) {
            console.error("인증번호 전송 오류", err);
            setError("인증번호 전송에 실패했습니다. 이메일을 다시 확인해주세요.");
        }
    };

    // 입력한 인증번호 검증
    const handleVerifyCode = async () => {
        setError(null);
        if (!verificationCode) {
            setError("인증번호를 입력해주세요.");
            return;
        }

        try {
            // 백엔드에 이메일과 인증번호를 보내 검증하는 API 호출
            const response = await apiClient.post("api/users/mail/verify-code", {
                email,
                verificationCode,
            });
            // 예를 들어, response.data.success가 true면 인증 성공으로 처리
            if (response.data.success) {
                setIsEmailVerified(true);
                setVerificationMessage("이메일 인증이 완료되었습니다.");
            } else {
                setError("인증번호가 올바르지 않습니다.");
            }
        } catch (err) {
            console.error("인증 확인 에러", err);
            setError("이메일 인증 확인에 실패했습니다.");
        }
    };

    // 회원가입 처리 (모든 입력 값과 이메일 인증, 비밀번호 확인 체크)
    const handleSignup = async (e) => {
        e.preventDefault();
        setError(null);

        if (!isEmailVerified) {
            setError("이메일 인증이 필요합니다.");
            return;
        }
        if (password !== confirmPassword) {
            setError("비밀번호와 비밀번호 확인이 일치하지 않습니다.");
            return;
        }
        try {
            // 백엔드 UserEntity에 맞춰서 데이터를 전송합니다.
            const response = await apiClient.post("api/users", {
                email,
                password,
                userFirstName: firstName,
                userLastName: lastName,
                phone,
            });
            if (response.data) {
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
                    <button type="button" onClick={handleSendVerificationCode}>
                        인증번호 발송
                    </button>
                </div>

                {/* 인증번호 발송 후, 인증번호 입력 폼을 노출 */}
                {verificationSent && !isEmailVerified && (
                    <div>
                        <label htmlFor="verificationCode">인증번호 입력</label>
                        <input
                            type="text"
                            id="verificationCode"
                            value={verificationCode}
                            onChange={(e) => setVerificationCode(e.target.value)}
                            required
                        />
                        <button type="button" onClick={handleVerifyCode}>
                            인증번호 확인
                        </button>
                    </div>
                )}

                {verificationMessage && <p className="verification-message">{verificationMessage}</p>}

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
                <div>
                    <label htmlFor="confirmPassword">비밀번호 확인</label>
                    <input
                        type="password"
                        id="confirmPassword"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
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
