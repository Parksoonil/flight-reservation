import { useEffect } from "react";

const airportCoords = {
    "김포국제공항": { lat: 37.5585, lng: 126.7902 },
    "인천국제공항": { lat: 37.4602, lng: 126.4407 },
    "김해국제공항": { lat: 35.1796, lng: 128.9381 },
    "제주국제공항": { lat: 33.5104, lng: 126.4910 },
    "청주국제공항": { lat: 36.7179, lng: 127.4990 },
    "무안국제공항": { lat: 34.9914, lng: 126.3828 },
    "양양국제공항": { lat: 38.0613, lng: 128.6690 },
    "대구국제공항": { lat: 35.8941, lng: 128.6585 }, // ✅ 추가
};

function MapWithPath({ flights }) {
    useEffect(() => {
        const script = document.createElement("script");
        script.src =
            "https://dapi.kakao.com/v2/maps/sdk.js?appkey=2e75cd437fa459df56e78c07d4af052b&autoload=false";
        script.async = true;

        script.onload = () => {
            window.kakao.maps.load(() => {
                const container = document.getElementById("path-map");

                // 지도 중심을 계산: 첫 항공편 기준 중간점
                let defaultCenter = new window.kakao.maps.LatLng(36.5, 128.0); // 기본값
                if (flights.length > 0) {
                    const from = airportCoords[flights[0].departureName];
                    const to = airportCoords[flights[0].arrivalName];
                    if (from && to) {
                        const midLat = (from.lat + to.lat) / 2;
                        const midLng = (from.lng + to.lng) / 2;
                        defaultCenter = new window.kakao.maps.LatLng(midLat, midLng);
                    }
                }

                const map = new window.kakao.maps.Map(container, {
                    center: defaultCenter,
                    level: 14,
                });

                flights.forEach((flight) => {
                    const from = airportCoords[flight.departureName];
                    const to = airportCoords[flight.arrivalName];
                    if (!from || !to) return;

                    const linePath = [
                        new window.kakao.maps.LatLng(from.lat, from.lng),
                        new window.kakao.maps.LatLng(to.lat, to.lng),
                    ];

                    new window.kakao.maps.Polyline({
                        map,
                        path: linePath,
                        strokeWeight: 4,
                        strokeColor: "#1e90ff",
                        strokeOpacity: 0.9,
                        strokeStyle: "solid",
                    });

                    new window.kakao.maps.Marker({
                        map,
                        position: new window.kakao.maps.LatLng(from.lat, from.lng),
                        title: "출발지: " + flight.departureName,
                    });

                    new window.kakao.maps.Marker({
                        map,
                        position: new window.kakao.maps.LatLng(to.lat, to.lng),
                        title: "도착지: " + flight.arrivalName,
                    });
                });
            });
        };

        document.head.appendChild(script);
    }, [flights]);

    return (
        <div
            id="path-map"
            style={{
                width: "40%",
                height: "400px",
                marginBottom: "1rem",
                borderRadius: "12px",
                border: "1px solid #ccc",
                boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
            }}
        />
    );
}

export default MapWithPath;
