import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import AirportSelectModal from "./AirportSelectModal.jsx";
import "./SearchFlight.css";

const SearchFlight = () => {
  const navigate = useNavigate();

  const [tripType, setTripType] = useState("round");
  const [departure, setDeparture] = useState({ name: "인천", code: "ICN" });
  const [arrival, setArrival] = useState({ name: "김포", code: "GMP" });
  const [date, setDate] = useState("");
  const [returnDate, setReturnDate] = useState("");
  const searchRef = useRef(null);

  const [isDepartureModalOpen, setIsDepartureModalOpen] = useState(false);
  const [isArrivalModalOpen, setIsArrivalModalOpen] = useState(false);

  const handleSearch = () => {
    if (!departure || !arrival) {
      alert("출발지와 도착지를 선택하세요.");
      return;
    }

    const searchData = {
      tripType,
      departure: departure.name,
      arrival: arrival.name,
      departureCode: departure.code,
      arrivalCode: arrival.code,
      date,
      returnDate
    };

    navigate("/flight", { state: searchData });
  };

  const handleSwap = () => {
    const temp = departure;
    setDeparture(arrival);
    setArrival(temp);
  };

  const handleReset = () => {
    setTripType("round");
    setDeparture({ name: "인천", code: "ICN" });
    setArrival({ name: "김포", code: "GMP" });
    setDate("");
    setReturnDate("");
  };

  return (
    <div className="flight-search-box">
      <h2>항공권 검색</h2>
      {/* 왕복/편도 탭 */}
      <div className="trip-tabs">
        <button
          className={tripType === "round" ? "active" : ""}
          onClick={() => setTripType("round")}
        >
          왕복
        </button>
        <button
          className={tripType === "oneway" ? "active" : ""}
          onClick={() => setTripType("oneway")}
        >
          편도
        </button>
      </div>

      {/* 출발지, 도착지 선택 */}
      <div className="airport-row">
        <div className="airport-box" onClick={() => setIsDepartureModalOpen(true)} ref={searchRef} >
          <div className="airport-label">{departure.name}</div>
          <div className="airport-code">{departure.code} <span>▼</span></div>
        </div>

        <button type="button" className="swap-btn" onClick={handleSwap}>
          ⇄
        </button>

        <div className="airport-box" onClick={() => setIsArrivalModalOpen(true)} ref={searchRef} >
          <div className="airport-label">{arrival.name}</div>
          <div className="airport-code">{arrival.code} <span>▼</span></div>
        </div>
      </div>

      {/* 공항 모달 */}
      {isDepartureModalOpen && (
        <AirportSelectModal
          onClose={() => setIsDepartureModalOpen(false)}
          triggerRef={searchRef} // 모달에 triggerRef 전달
          onSelect={(airport) => setDeparture(airport)}
        />
      )}

      {isArrivalModalOpen && (
        <AirportSelectModal
          onClose={() => setIsArrivalModalOpen(false)}
          triggerRef={searchRef} // 모달에 triggerRef 전달
          onSelect={(airport) => setArrival(airport)}
        />
      )}

      {/* 날짜 선택 */}
      <div className="date-row">
        <input
          type="date"
          value={date}
          onChange={(e) => setDate(e.target.value)}
        />
        {tripType === "round" && (
          <input
            type="date"
            value={returnDate}
            onChange={(e) => setReturnDate(e.target.value)}
          />
        )}
      </div>

      {/* 버튼 */}
      <div className="action-row">
        <button className="reset-btn" onClick={handleReset}>
          ↻ 초기화
        </button>
        <button className="search-btn" onClick={handleSearch}>
          검색
        </button>
      </div>
    </div>
  );
};

export default SearchFlight;
