import { useSearchParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import apiClient from '../apiClient';

function GroupPayment() {
  const [params] = useSearchParams();
  const groupId = params.get("groupId");
  const uId = Number(params.get("uId"));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!groupId || isNaN(uId)) {
      alert("잘못된 접근입니다.");
      window.close();
    }
  }, []);

  const handlePay = async () => {
    try {
      setLoading(true);
      await apiClient.post(`/api/reservations/payments/virtual/by-group`, null, {
        params: { groupId, uId }
      });

      alert("✅ 단체 결제가 완료되었습니다.");
      window.opener?.postMessage("payment-complete", "*");
      window.close();
    } catch (e) {
      alert("❌ 결제 실패");
      setError("결제 요청 중 오류가 발생했습니다.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: 30 }}>
      <h2>💳 단체 결제창</h2>
      <p><strong>Group ID:</strong> {groupId}</p>
      <button onClick={handlePay} disabled={loading}>
        {loading ? "결제 중..." : "결제하기"}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
}

export default GroupPayment;
