import { GoogleMap, useLoadScript, OverlayView } from "@react-google-maps/api";
import {useRef, useState} from "react";
import {allAirports} from "../data/allAirports.js";

const containerStyle = {
    width: "100%",
    height: "550px",
};

const center = { lat: 35, lng: 130 };

const continentHubCodes = ["ICN", "SIN", "DXB", "LHR", "JFK", "GRU", "JNB","SYD"];



function GoogleMapInternational() {
    const [departure, setDeparture] = useState(null);
    const [arrival, setArrival] = useState(null);
    const [visibleAirports, setVisibleAirports] = useState([]);
    const mapRef = useRef(null); // 지도 객체 저장용
    const [hovered, setHovered] = useState(null);


    const { isLoaded } = useLoadScript({
        googleMapsApiKey: import.meta.env.VITE_GOOGLE_MAPS_API_KEY,
    });

    const handleClick = (airport) => {
        if (!departure) setDeparture(airport.name);
        else if (!arrival && airport.name !== departure) setArrival(airport.name);
        else {
            setDeparture(null);
            setArrival(null);
        }
    };

    const updateVisibleAirports = (map) => {
        const bounds = map.getBounds();
        const zoom = map.getZoom();
        if (!bounds) return;

        const filtered = allAirports.filter((airport) => {
            const pos = new window.google.maps.LatLng(airport.lat, airport.lng);
            return (
                airport.type !== "domestic" &&
                bounds.contains(pos) &&
                (
                    zoom >= 10 ||                              // 가까이 확대: 다 보여줌
                    (zoom >= 4.5 && airport.price <= 1000000) ||  // 중간 줌: 인기 공항들
                    (zoom >= 3.5 && airport.code === "HND") ||
                    (zoom >= 2 && continentHubCodes.includes(airport.code))         // 가장 멀리: 인천만
                )
            );
        });


        setVisibleAirports(filtered);
    };


    if (!isLoaded) return <div>지도 로딩 중...</div>;

    return (
        <div style={{ display: "flex", gap: "2rem" ,  borderRadius: "12px", }}>
            <GoogleMap mapContainerStyle={containerStyle} center={center} zoom={2.7}
             onLoad={(map) => {
                 mapRef.current = map;
                 updateVisibleAirports(map);
             }}

             onIdle={() => updateVisibleAirports(mapRef.current)}
                       options={{
                           minZoom: 2,
                           maxZoom: 10
                       }}
            >
                {visibleAirports.map((airport) => (
                    <OverlayView
                        key={airport.code}
                        position={{ lat: airport.lat, lng: airport.lng }}
                        mapPaneName={OverlayView.OVERLAY_MOUSE_TARGET}
                    >
                        <div
                            onClick={() => handleClick(airport)}
                            onMouseEnter={() => setHovered(airport.code)} //ZIndex 이용해서 마우스호버
                            onMouseLeave={() => setHovered(null)}
                            style={{
                                width: "115px",         // ✅ 고정 너비 설정
                                background: "white",
                                color: "#007bff",
                                zIndex: hovered === airport.code ? 999 : 1,
                                position: "relative",
                                padding: "12px 15px",
                                borderRadius: "8px",
                                fontSize: "15px",
                                lineHeight: "1.4",
                                textAline:"center",
                                cursor: "pointer",
                                whiteSpace: "nowrap",
                                transform: "translate(-50%, -100%)",
                                boxShadow: airport.name === departure || airport.name === arrival
                                    ? "0 0 10px rgba(0,123,255,0.8)"
                                    : "0 4px 12px rgba(0, 0, 0, 0.1)",
                            }}
                        >
                            <div style={{ fontWeight: "600" }}>{airport.name}</div>
                            <div style={{ color: "#f84949", fontWeight: "bold" }}>
                                ₩{airport.price.toLocaleString()}~
                            </div>
                        </div>
                    </OverlayView>
                ))}
            </GoogleMap>

            <div style={{ width: "35%" }}>
                <h3 style={{ color: "#007bff" }}>선택된 항공편</h3>
                <p>
                    <strong>출발지:</strong> {departure || "미정"} <br />
                    <strong>도착지:</strong> {arrival || "미정"}
                </p>
            </div>
        </div>
    );
}

export default GoogleMapInternational;
