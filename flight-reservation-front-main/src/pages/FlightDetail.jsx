import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setFlight } from '../data/reservationSlice';
import '../style/FlightDetail.css';

function FlightDetail() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const goFlight = state?.goFlight;
  const backFlight = state?.backFlight;
  const oneWayFlight = state?.flight;

  const formatTime = (str) =>
    new Date(str).toLocaleTimeString("ko-KR", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });

  const handleBookFlight = () => {
    if (oneWayFlight) {
      dispatch(setFlight({ goFlight: oneWayFlight }));
    } else if (goFlight && backFlight) {
      dispatch(setFlight({ goFlight, backFlight }));
    } else {
      console.error("선택된 항공편 정보가 없습니다.");
      return;
    }

    navigate("/loading");
  };

  const renderFlightTable = (flight, title) => (
    <div className="flight-section">
      <h3>{title}</h3>
      <table className="flight-detail-table">
        <tbody>
          <tr>
            <th>항공사</th>
            <td>{flight.aircraftType}</td>
          </tr>
          <tr>
            <th>출발 날짜</th>
            <td>{flight.departureTime.split("T")[0]}</td>
          </tr>
          <tr>
            <th>출발지 / 도착지</th>
            <td>{flight.departureName} / {flight.arrivalName}</td>
          </tr>
          <tr>
            <th>출발 시간 / 도착 시간</th>
            <td>{formatTime(flight.departureTime)} / {formatTime(flight.arrivalTime)}</td>
          </tr>
          <tr>
            <th>총 좌석</th>
            <td>{flight.seatCount}석</td>
          </tr>
        </tbody>
      </table>
    </div>
  );

  return (
    <div className="flight-detail-container">
      <h2>항공편 상세 정보</h2>

      {oneWayFlight && renderFlightTable(oneWayFlight, "🛫 편도 항공편")}
      {goFlight && backFlight && (
        <>
          {renderFlightTable(goFlight, "🛫 출발 항공편")}
          {renderFlightTable(backFlight, "🛬 복귀 항공편")}
        </>
      )}

      <div className="button-group">
        <button className="book-button" onClick={handleBookFlight}>
          예매하기
        </button>
      </div>
    </div>
  );
}

export default FlightDetail;
