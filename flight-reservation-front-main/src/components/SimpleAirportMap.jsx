import { useEffect, useRef, useState } from "react";
import axios from "axios";
import "../style/SimpleAirportMap.css";
import apiClient from "../apiClient.jsx";

const airportCoords = {
    "김포국제공항": { lat: 37.5585, lng: 126.7902 },
    "인천국제공항": { lat: 37.1002, lng: 126.4407 },
    "김해국제공항": { lat: 35.1796, lng: 128.9381 },
    "제주국제공항": { lat: 33.5104, lng: 126.4910 },
    "청주국제공항": { lat: 36.7179, lng: 127.4990 },
    "무안국제공항": { lat: 34.9914, lng: 126.3828 },
    "양양국제공항": { lat: 37.8813, lng: 128.6690 },
    "대구국제공항": { lat: 35.8941, lng: 128.6585 },
};

function SimpleAirportMap() {
    const [departure, setDeparture] = useState(null);
    const [arrival, setArrival] = useState(null);
    const [flights, setFlights] = useState([]);

    const mapRef = useRef(null);

    const fetchFlightList = async (from, to) => {
        try {
            const res = await apiClient.get(
                `/api/flights/search?tripType=oneway&departure=${from}&arrival=${to}`
            );
            setFlights(res.data.content);
            console.log(res.data);
        } catch (err) {
            console.error("항공편 불러오기 실패:", err);
        }
    };

    useEffect(() => {
        const script = document.createElement("script");
        script.src =
            "https://dapi.kakao.com/v2/maps/sdk.js?appkey=2e75cd437fa459df56e78c07d4af052b&autoload=false";
        script.async = true;

        script.onload = () => {
            window.kakao.maps.load(() => {
                const container = document.getElementById("airport-map");
                const map = new window.kakao.maps.Map(container, {
                    center: new window.kakao.maps.LatLng(35.8, 127.5),
                    level: 13,
                });

                mapRef.current = map;

                Object.entries(airportCoords).forEach(([name, { lat, lng }]) => {
                    const position = new window.kakao.maps.LatLng(lat, lng);

                    // 말풍선 마커 스타일 (커스텀 오버레이)
                    const markerContent = document.createElement("div");
                    markerContent.className = `custom-marker ${name === departure || name === arrival ? "selected" : ""
                        }`;
                    markerContent.innerText = name;
                    markerContent.onclick = () => {
                        if (!departure) {
                            setDeparture(name);
                        } else if (!arrival && name !== departure) {
                            setArrival(name);
                            fetchFlightList(departure, name);
                        } else if (name === departure) {
                            setDeparture(null);
                            setArrival(null);
                            setFlights([]);
                        } else if (name === arrival) {
                            setArrival(null);
                            setFlights([]);
                        }
                    };

                    new window.kakao.maps.CustomOverlay({
                        map,
                        position,
                        content: markerContent,
                        yAnchor: 1,
                    });
                });
            });
        };

        document.head.appendChild(script);
    }, [departure, arrival]);

    return (
        <div className="map-layout">
            {/* 지도 영역 */}
            <div id="airport-map" />

            {/* 오른쪽 리스트 영역 */}
            <div className="flight-list-container">
                {/* 출발지 및 도착지 정보 */}
                <div className="flight-info">
                    <h3 className="flight-list-title">선택된 항공편</h3>
                    <div style={{ marginBottom: "1rem" }}>
                        <strong>출발지:</strong> {departure || "미정"} | <strong>도착지:</strong> {arrival || "미정"}
                    </div>
                </div>

                {/* 리스트만 따로 스크롤되게 */}
                <div className="flight-list-scroll">
                    {flights.length > 0 ? (
                        flights.map((flight, idx) => (
                            <div key={idx} className="flight-list-item">
                                ✈ {flight.departureName} → {flight.arrivalName}
                                <br />
                                🗓 {flight.departureTime?.split("T")[0]}
                            </div>
                        ))
                    ) : (
                        <div className="no-flight-message">
                            <span role="img" aria-label="airplane" className="emoji">✈️</span>
                            <p>출발지와 도착지를 지도에서 선택해주세요.</p>
                        </div>
                    )}
                </div>
            </div>

        </div>
    );
}

export default SimpleAirportMap;