import { useEffect, useState } from "react";
import axios from "axios";
import './FlightList.css';

function FlightList({ filters, allFlights = [], onSelectedFlights }) {
    const [oneWayFlights, setOneWayFlights] = useState([]);
    const [roundTripFlights, setRoundTripFlights] = useState({ goList: [], backList: [] });
    const [selectedFlightId, setSelectedFlightId] = useState(null);
    const [page, setPage] = useState(0);

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
                    const uri = isRound
                        ? "http://localhost:8443/api/flights/search/split"
                        : "http://localhost:8443/api/flights/search";

                    const res = await axios.get(uri, {
                        params: {
                            ...cleanParams,
                            page,
                            size: 10,
                        },
                    });

                    console.log("✈️ 요청 URI:", uri);
                    console.log("📦 응답 데이터:", res.data);

                    if (isRound) {
                        const { goList = [], backList = [] } = res.data;
                        setRoundTripFlights({ goList, backList });
                        setOneWayFlights([]);
                    } else {
                        const content = Array.isArray(res.data?.content)
                            ? res.data.content
                            : Array.isArray(res.data)
                                ? res.data
                                : [];

                        setOneWayFlights(content);
                        setRoundTripFlights({ goList: [], backList: [] });
                    }

                    setSelectedFlightId(null);
                } else {
                    setOneWayFlights(allFlights);
                    setSelectedFlightId(null);
                }
            } catch (error) {
                console.error("❌ 항공편 데이터 로딩 실패:", error);
            }
        };

        fetchFlights();
    }, [filters, allFlights, page]);

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

    const handleSelectedFlight = (flight) => {
        setSelectedFlightId(flight.id);

        if (filters?.tripType === "round") {
            onSelectedFlights((prev) => {
                const exists = prev.find((f) => f.id === flight.id);
                const updated = exists ? prev : [...prev, flight];
                return updated.slice(0, 2);
            });
        } else {
            onSelectedFlights([flight]);
        }
    };

    const renderFlightCard = (flight, idx, type) => (
        <div
            key={`${type}-${flight.id}-${idx}`}
            className={`flight-card ${selectedFlightId === flight.id ? 'selected' : ''}`}
            onClick={() => handleSelectedFlight(flight)}
        >
            <div className="section section-left">
                <h3>{flight.aircraftType}</h3>
                <p>{flight.departureTime?.split("T")[0]}</p>
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

    const renderOneWay = () => {
        if (!Array.isArray(oneWayFlights)) {
            console.warn("❗ oneWayFlights가 배열이 아님!", oneWayFlights);
            return <p>😢 항공편 정보를 불러오지 못했습니다.</p>;
        }

        return oneWayFlights.map((flight, idx) =>
            renderFlightCard(flight, idx, "oneway")
        );
    };

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
            {filters?.tripType === "round" ? renderRoundTrip() : renderOneWay()}
        </div>
    );
}

export default FlightList;
