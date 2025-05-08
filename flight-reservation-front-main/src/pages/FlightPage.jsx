import { useEffect, useState } from "react";
import SearchFlight from "../components/SearchFlight.jsx";
import FlightList from "./FlightList.jsx";
import axios from "axios";
import MapWithPath from "../components/MapWithPath.jsx";
import "./FlightPage.css"
import GoogleMap from "../components/GoogleMap.jsx";
import apiClient from "../apiClient.jsx";
import {useNavigate} from "react-router-dom";

function FlightPage() {

    const [filters, setFilters] = useState(null);
    const [allFlights, setAllFlights] = useState([]);
    const [selectedFlights, setSelectedFlights] = useState([]);
    const navi = new useNavigate();

    useEffect(() => {
        const fetchInitial = async () => {
            try {
                const res = await apiClient.get("/api/flights",{
                    params: {
                        page: 0,
                        size: 10,
                    },
                });
                setAllFlights(res.data);
                console.log(res);
            } catch (error) {
                console.error("초기 항공편 데이터 불러오기 실패", error);
            }
        };

        if (!filters) {
            fetchInitial();
        }
    }, [filters]);

    const handleSearch = (searchData) => {
        setFilters(searchData); // 상태 전달
    };

    const sendTokafka = async () =>{
        try {
            for (const flight of selectedFlights) {
                await apiClient.post("/api/kafka/publish" ,flight)
            }
            alert("Kafka 전송완료");
            navi("/loading");
        } catch (error) {
            console.error("Kafka 전송실패:", error);
            alert("전송실패");
        }
    }


    return (
        <div>
            <SearchFlight onSearch={handleSearch} />

            <div className="selected-flights-box">
                <MapWithPath flights={selectedFlights} />

                <div className="flight-info-box">
                    <h3 className="mb-5">선택된 항공편</h3>

                    <div className="flight-pair-container1">
                        {selectedFlights.length === 2 ? (
                            <>
                                {/* 출발 항공편 */}
                                <div className="flight-card1">
                                    <p className="route1">
                                        ✈ {selectedFlights[0].departureName} → {selectedFlights[0].arrivalName}
                                    </p>
                                    <p className="date1">🗓 {selectedFlights[0].departureTime?.split("T")[0]}</p>
                                </div>

                                {/* 돌아오는 항공편 */}
                                <div className="flight-card1">
                                    <p className="route1">
                                        ✈ {selectedFlights[1].departureName} → {selectedFlights[1].arrivalName}
                                    </p>
                                    <p className="date1">🗓 {selectedFlights[1].departureTime?.split("T")[0]}</p>
                                </div>
                            </>
                        ) : (
                            // 편도일 때는 그대로
                            selectedFlights.map((flight, idx) => (
                                <div key={idx} className="flight-card1">
                                    <p className="route1">
                                        ✈ {flight.departureName} → {flight.arrivalName}
                                    </p>
                                    <p className="date1">🗓 {flight.departureTime?.split("T")[0]}</p>
                                </div>
                            ))
                        )}
                    </div>


                    <button className="send-button mt-3" onClick={sendTokafka}>
                        예약하기
                    </button>
                </div>
            </div>

            <FlightList
                filters={filters}
                allFlights={allFlights}
                onSelectedFlights={setSelectedFlights}
            />
        </div>
    );

}

export default FlightPage;
