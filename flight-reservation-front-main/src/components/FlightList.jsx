import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import '../style/FlightList.css';

function FlightList({ filters, allFlights = [] }) {
    const [oneWayFlights, setOneWayFlights] = useState([]);
    const [roundTripFlights, setRoundTripFlights] = useState({ goList: [], backList: [] });
    const [selectedGoFlight, setSelectedGoFlight] = useState(null);  // 출발편 선택 상태
    const [selectedBackFlight, setSelectedBackFlight] = useState(null);  // 복귀편 선택 상태
    const [page, setPage] = useState(0);
    const [isBookingEnabled, setIsBookingEnabled] = useState(false); // 예매 버튼 활성화 상태
    const navigate = useNavigate();

    useEffect(() => {
        const fetchFlights = async () => {
            try {
                if (filters) {
                    const cleanParams = { ...filters };
                    Object.keys(cleanParams).forEach((key) => {
                        if (key !== "tripType" && cleanParams[key] === "") {
                            delete cleanParams[key];
                        }
                    });

                    const isRound = filters.tripType === "round";
                    const Uri = isRound
                        ? "http://localhost:8080/api/flights/search/split"
                        : "http://localhost:8080/api/flights/search";

                    const res = await axios.get(Uri, {
                        params: { ...cleanParams, page: page, size: 10 }
                    });

                    if (isRound) {
                        const { goList, backList } = res.data;
                        setRoundTripFlights({ goList, backList });
                        setOneWayFlights([]);
                    } else {
                        setOneWayFlights(res.data.content);
                        setRoundTripFlights({ goList: [], backList: [] });
                    }

                    setSelectedGoFlight(null);
                    setSelectedBackFlight(null);
                } else {
                    setOneWayFlights(allFlights);
                    setSelectedGoFlight(null);
                    setSelectedBackFlight(null);
                }
            } catch (error) {
                console.error("항공편 데이터 로딩 실패", error);
            }
        };

        fetchFlights();
    }, [filters, allFlights]);

    const tripType = filters?.tripType || "oneway";

    useEffect(() => {
        // 예매 버튼 활성화 조건 체크
        if (filters?.tripType === "round") {
            // 왕복일 때 출발편과 복귀편이 모두 선택되었는지 확인
            setIsBookingEnabled(selectedGoFlight && selectedBackFlight);
        } else {
            // 편도일 때는 하나의 항공편만 선택되어야 함
            setIsBookingEnabled(selectedGoFlight !== null);
        }
    }, [selectedGoFlight, selectedBackFlight, filters]);

    const formatTime = (str) =>
        new Date(str).toLocaleTimeString("ko-KR", {
            hour: "2-digit",
            minute: "2-digit",
            hour12: false,
        });

    const getFlightDuration = (start, end) => {
        const diff = new Date(end) - new Date(start);
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        return `${hours}시간 ${minutes}분`;
    };

    const handleFlightClick = (flight, type) => {
        if (filters?.tripType === "round") {
            if (type === "go") {
                setSelectedGoFlight(flight.id === selectedGoFlight ? null : flight.id); 
            } else if (type === "back") {
                setSelectedBackFlight(flight.id === selectedBackFlight ? null : flight.id);
            }
        } else {
            setSelectedGoFlight(flight.id === selectedGoFlight ? null : flight.id);
        }
    };

    const handleBookingClick = () => {
        if (filters?.tripType === "round") {
            navigate("/flight/detail", {
                state: { goFlight: roundTripFlights.goList.find(flight => flight.id === selectedGoFlight), backFlight: roundTripFlights.backList.find(flight => flight.id === selectedBackFlight) }
            });
        } else {
            navigate("/flight/detail", { state: { flight: oneWayFlights.find(flight => flight.id === selectedGoFlight) } });
        }
    };

    const renderFlightCard = (flight, idx, type) => (
        <div
            key={`${type}-${flight.id}-${idx}`}
            className={`flight-card ${
                (tripType === "round" && type === "go" && selectedGoFlight === flight.id) ||
                (tripType === "round" && type === "back" && selectedBackFlight === flight.id) ||
                (tripType === "oneway" && selectedGoFlight === flight.id)
                    ? 'selected' : ''
            }`}
            onClick={() => handleFlightClick(flight, type)}
        >
            <div className="section section-left">
                <h3>{flight.aircraftType}</h3>
                <p>{flight.departureTime.split("T")[0]}</p>
            </div>

            <div className="section section-center">
                <div className="center-twin">
                    <div className="time-info">
                        <p className="time">{formatTime(flight.departureTime)}</p>
                        <p className="location">{flight.departureName}</p>
                    </div>
                    <div className="duration-info">
                        ✈️ {getFlightDuration(flight.departureTime, flight.arrivalTime)}
                    </div>
                    <div className="time-info">
                        <p className="time">{formatTime(flight.arrivalTime)}</p>
                        <p className="location">{flight.arrivalName}</p>
                    </div>
                </div>
            </div>

            <div className="section section-right">
                <p className="price">₩ {flight.price}</p>
                <p className="seats">좌석 {flight.seatCount}석</p>
            </div>
        </div>
    );

    const renderOneWay = () =>
        oneWayFlights.map((flight, idx) => renderFlightCard(flight, idx, "oneway"));

    const renderRoundTrip = () => (
        <div className="round-trip-columns">
            <div className="column">
                <h3>✈️ 출발 항공편</h3>
                {roundTripFlights.goList.length > 0 ? (
                    roundTripFlights.goList.map((flight, idx) =>
                        renderFlightCard(flight, idx, "go")
                    )
                ) : (
                    <p>😢 출발 항공편이 없습니다.</p>
                )}
            </div>

            <div className="column">
                <h3>🛬 돌아오는 항공편</h3>
                {roundTripFlights.backList.length > 0 ? (
                    roundTripFlights.backList.map((flight, idx) =>
                        renderFlightCard(flight, idx, "back")
                    )
                ) : (
                    <p>😢 돌아오는 항공편이 없습니다.</p>
                )}
            </div>
        </div>
    );

    return (
        <div className={`flight-list ${filters?.tripType === "round" ? "wide-mode" : ""}`}>
            <button
                disabled={!isBookingEnabled}
                onClick={handleBookingClick}
                className="booking-button"
            >
                예매하기
            </button>
            {filters?.tripType === "round" ? renderRoundTrip() : renderOneWay()}
        </div>
    );
}

export default FlightList;
