import { useState } from "react";
import "./SearchFlight.css";
import AirportSelectModal from "./AirportSelectModal.jsx";

const SearchFlight = ({ onSearch }) => {
  const [isDepartureModalOpen, setIsDepartureModalOpen] = useState(false);
  const [isArrivalModalOpen, setIsArrivalModalOpen] = useState(false);

  const [tripType, setTripType] = useState("round");
  const [departure, setDeparture] = useState({ name: "인천", code: "ICN" });
  const [arrival, setArrival] = useState({ name: "김포", code: "GMP" });
  const [arrivalCode , setArrivalCode] = useState("GMP");
  const [date, setDate] = useState("");
  const [returnDate, setReturnDate] = useState("");

  const handleSearch = () => {
    if (!departure || !arrival) {
      alert("출발지와 도착지를 선택하세요.");
      return;
    }
    onSearch({
      tripType,
      departure: departure.name,
      arrival: arrival.name,
      departureCode: departure.code,
      arrivalCode: arrival.code,
      date,
      returnDate
    });
  };

  const handleSwap = () => {
    const temp = departure;
    setDeparture(arrival);
    setArrival(temp);
  };

  return (
      <div className="flight-search-box">
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
          <h2 style={{ marginLeft: "275px" }}>항공권 검색</h2>
        </div>

        <div className="form-row">
          <div className="form-row select-boxes">
            <div className="airport-box" onClick={() => setIsDepartureModalOpen(true)}>
              <div className="airport-label">{departure.name}</div>
              <div className="airport-code">{departure.code} <span>▼</span></div>
            </div>
            <button type="button" onClick={handleSwap}>⇄</button>
            <div className="airport-box" onClick={() => setIsArrivalModalOpen(true)}>
              <div className="airporrnt-label">{arrival.name}</div>
              <div className="airport-code">{arrival.code} <span>▼</span></div>
            </div>
          </div>


          {isDepartureModalOpen && (
              <AirportSelectModal
                  onClose={() => setIsDepartureModalOpen(false)}
                  onSelect={(airport) =>{ setDeparture(airport) } }
              />
          )}

          {isArrivalModalOpen && (
              <AirportSelectModal
                  onClose={() => setIsArrivalModalOpen(false)}
                  onSelect={(airport) => setArrival(airport)}
              />
          )}



          <div className="form-row">
            <input
                type="date"
                value={date}
                onChange={(e) => setDate(e.target.value)}
            />
          </div>

          {tripType === "round" && (
              <div className="form-row">
                <input
                    type="date"
                    value={returnDate}
                    onChange={(e) => setReturnDate(e.target.value)}
                />
              </div>
          )}

          <div className="form-row">
            <button className="search-btn" onClick={handleSearch}>
              검색
            </button>
          </div>
        </div>

      </div>
  );
};

export default SearchFlight;
