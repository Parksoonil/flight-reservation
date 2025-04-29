import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

function RSVPayment() {
    const navigate = useNavigate();
    const [paymentComplete, setPaymentComplete] = useState(false);
    const [popupOpened, setPopupOpened] = useState(false);
    const [showRetryMessage, setShowRetryMessage] = useState(false);
    const [popupWindow, setPopupWindow] = useState(null);

    // 팝업에서 메시지를 받기 위한 이벤트 리스너 등록
    useEffect(() => {
        const handleMessage = (event) => {
            if (event.data === 'payment-complete') {
                setPaymentComplete(true);
                setShowRetryMessage(false);
            }
        };

        window.addEventListener('message', handleMessage);

        return () => {
            window.removeEventListener('message', handleMessage);
        };
    }, []);

    // 컴포넌트 마운트 시 팝업 열기
    useEffect(() => {
        openPaymentPopup();
    }, []);

    const openPaymentPopup = () => {
        const popup = window.open(
            '/payment',
            'PaymentPopup',
            'width=400,height=300'
        );
        if (popup) {
            setPopupOpened(true);
            setPopupWindow(popup);
            setShowRetryMessage(false);
        } else {
            setShowRetryMessage(true); // 팝업 차단된 경우 등
        }
    };

    useEffect(() => {
        if (paymentComplete) {
            const timer = setTimeout(() => {
                navigate(`/rsv/result`);
            }, 2000);

            return () => clearTimeout(timer);
        }
    }, [paymentComplete, navigate]);

    const handleGoBack = () => {
        navigate(-1);
    };

    return (
        <div>
            <h1>결제</h1>
            {paymentComplete ? (
                <p>✅ 결제가 완료되었습니다!</p>
            ) : (
                <div>
                    <p>결제 진행 중...</p>
                    <p>
                        팝업이 뜨지 않나요?{' '}
                        <span
                            style={{ color: 'blue', textDecoration: 'underline', cursor: 'pointer' }}
                            onClick={openPaymentPopup}
                        >
                            클릭
                        </span>
                    </p>
                    <button onClick={handleGoBack}>뒤로가기</button>
                </div>

            )}
        </div>
    );
}

export default RSVPayment;
