import { useLocation, useNavigate } from "react-router-dom";
import "../../styles/ReservationComplete.css";

function ReservationComplete() {
    const navigate = useNavigate();
    const location = useLocation();
    const from = location.state?.from || "/"

    return (
        <div className="reservation-complete-container">
            <h2>🎉 예매가 완료되었습니다!</h2>
            <p className="message">결제는 <strong>마이페이지</strong>에서 진행하세요.</p>
            <div className="button-group">
                <button onClick={() => navigate("/mypage")}>마이페이지</button>
                <button onClick={() => navigate("/")}>홈으로 이동</button>
                <button onClick={() => navigate(from)}>이전 상세 페이지로 돌아가기</button>
            </div>
        </div>
    );
}

export default ReservationComplete;
