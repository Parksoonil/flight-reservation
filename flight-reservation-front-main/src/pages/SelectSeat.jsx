import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setSelectedSeats } from '../data/reservationSlice';
import '../style/SelectSeat.css';

function SelectSeat() {
    const navigate = useNavigate();
    const dispatch = useDispatch();
    const [selectedSeats, setSelectedSeatsState] = useState([]);

    const totalSeats = 20;

    const handleSeatClick = (seatNumber) => {
        setSelectedSeatsState((prev) =>
            prev.includes(seatNumber)
                ? prev.filter((seat) => seat !== seatNumber)
                : [...prev, seatNumber]
        );
    };

    const handleNext = () => {
        if (selectedSeats.length === 0) {
            alert('좌석을 한 개 이상 선택해주세요.');
            return;
        }
        dispatch(setSelectedSeats(selectedSeats));
        navigate(`/rsv/detail`);
    };

    const handleGoBack = () => {
        navigate(-1);
    };

    return (
        <div className="select-seat-container">
            <h1>좌석 선택</h1>
            <div className="seat-container">
                {Array.from({ length: totalSeats }, (_, i) => i + 1).map((seatNumber) => (
                    <button
                        key={seatNumber}
                        className={`seat ${selectedSeats.includes(seatNumber) ? 'selected' : ''}`}
                        onClick={() => handleSeatClick(seatNumber)}
                    >
                        {seatNumber}
                    </button>
                ))}
            </div>
            <div className="button-group" style={{ marginTop: '20px' }}>
                <button onClick={handleNext}>다음 단계</button>
                <button onClick={handleGoBack}>뒤로 가기</button>
            </div>
        </div>
    );
}

export default SelectSeat;