import { useEffect } from 'react';

function Payment() {
    useEffect(() => {
        window.opener?.focus(); // 부모 창 포커스
    }, []);

    const handleComplete = () => {
        if (window.opener) {
            window.opener.postMessage('payment-complete', '*');
            window.close();
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <h2>가상 결제창</h2>
            <p>여기서 결제를 완료해주세요.</p>
            <button onClick={handleComplete}>결제 완료</button>
        </div>
    );
}

export default Payment;
