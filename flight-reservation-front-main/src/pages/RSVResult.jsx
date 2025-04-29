import { useSelector } from 'react-redux';
import { useEffect, useState } from 'react';
import axios from 'axios';
import apiClient from "../apiClient.jsx";

function RSVResult() {
    const { flight, selectedSeats, contact, request } = useSelector((state) => state.reservation);
    const [status, setStatus] = useState('idle'); // 'idle' | 'saving' | 'success' | 'error'

    const formatTime = (str) =>
        new Date(str).toLocaleTimeString("ko-KR", {
            hour: "2-digit",
            minute: "2-digit",
            hour12: false,
        });

        useEffect(() => {
            const saveReservation = async () => {
                setStatus('saving');
        
                const loggedUser = localStorage.getItem('user');
                const user = loggedUser ? JSON.parse(loggedUser) : null;
        
                const baseData = {
                    selectedSeats,
                    contact,
                    request,
                    userId: user?.id,
                    username: user?.username,
                    paymentComplete: true,
                    reservedAt: new Date().toISOString(),
                };
        
                const saveSingleReservation = async (flightData) => {
                    const reservation = {
                        ...baseData,
                        flight: flightData,
                    };
        
                    try {
                        await apiClient.post('api/reservations', reservation);
                    } catch (error) {
                        throw error;
                    }
                };
        
                try {
                    if (flight?.goFlight) {
                        await saveSingleReservation(flight.goFlight);
                    }
        
                    if (flight?.backFlight) {
                        await saveSingleReservation(flight.backFlight);
                    }
        
                    setStatus('success');
                } catch (error) {
                    console.error('예약 저장 실패:', error);
                    setStatus('error');
                }
            };
        
            if (flight?.goFlight) {
                saveReservation();
            }
        }, [flight, selectedSeats, contact, request]);
        

    return (
        <div style={{ padding: '20px' }}>
            <h1>예약 최종 확인</h1>

            {status === 'saving' && <p>예약 정보를 저장 중입니다...</p>}
            {status === 'success' && <p style={{ color: 'green' }}>예약이 성공적으로 저장되었습니다!</p>}
            {status === 'error' && <p style={{ color: 'red' }}>예약 저장에 실패했습니다. 다시 시도해주세요.</p>}

            <hr />

            <h3>선택한 항공편</h3>

            {flight?.goFlight && (
                <div style={{ marginBottom: '20px' }}>
                    <strong>항공사:</strong> {flight.goFlight.aircraftType} <br />
                    <strong>출발날짜:</strong> {flight.goFlight.departureTime.split("T")[0]} <br />
                    <strong>출발지:</strong> {flight.goFlight.departureName} <br />
                    <strong>도착지:</strong> {flight.goFlight.arrivalName} <br />
                    <strong>출발 시간:</strong> {formatTime(flight.goFlight.departureTime)} <br />
                    <strong>도착 시간:</strong> {formatTime(flight.goFlight.arrivalTime)} <br />
                </div>
            )}

            {flight?.backFlight && (
                <div style={{ marginBottom: '20px' }}>
                    <strong>복귀 - 항공사:</strong> {flight.backFlight.aircraftType} <br />
                    <strong>복귀 - 출발날짜:</strong> {flight.backFlight.departureTime.split("T")[0]} <br />
                    <strong>복귀 - 출발지:</strong> {flight.backFlight.departureName} <br />
                    <strong>복귀 - 도착지:</strong> {flight.backFlight.arrivalName} <br />
                    <strong>복귀 - 출발 시간:</strong> {formatTime(flight.backFlight.departureTime)} <br />
                    <strong>복귀 - 도착 시간:</strong> {formatTime(flight.backFlight.arrivalTime)} <br />
                </div>
            )}

            <h3>선택한 좌석</h3>
            <p>{selectedSeats?.length ? selectedSeats.join(', ') + ' 번' : '선택된 좌석 없음'}</p>

            <h3>연락처</h3>
            <p>{contact || '없음'}</p>

            <h3>요청사항</h3>
            <p>{request || '없음'}</p>
        </div>
    );
}

export default RSVResult;
