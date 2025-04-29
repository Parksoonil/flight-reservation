import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { setContact, setRequest } from '../data/reservationSlice';

function ReservationDetail() {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [contact, setContactState] = useState('');
    const [request, setRequestState] = useState('');

    const handleNext = () => {
        if (!contact.trim()) {
            alert('연락처를 입력해주세요.');
            return;
        }

        dispatch(setContact(contact));
        dispatch(setRequest(request));
        navigate('/rsv/payment');
    };

    const handleBack = () => {
        navigate(-1);
    };

    return (
        <div className="reservation-detail-container" style={{ padding: '20px', maxWidth: '400px', margin: '0 auto' }}>
            <h2>추가 정보 입력</h2>

            <div style={{ marginBottom: '15px' }}>
                <label>연락처 (필수):</label>
                <input
                    type="text"
                    value={contact}
                    onChange={(e) => setContactState(e.target.value)}
                    placeholder="010-xxxx-xxxx"
                    style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
            </div>

            <div style={{ marginBottom: '15px' }}>
                <label>요청사항 (선택):</label>
                <textarea
                    value={request}
                    onChange={(e) => setRequestState(e.target.value)}
                    placeholder="기내식, 휠체어 요청 등"
                    rows={4}
                    style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <button onClick={handleBack}>뒤로가기</button>
                <button onClick={handleNext}>결제</button>
            </div>
        </div>
    );
}

export default ReservationDetail;
