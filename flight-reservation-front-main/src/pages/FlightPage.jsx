import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import axios from "axios";
import FlightList from "../components/FlightList";
import SearchFlight from "../components/SearchFlight";
import MapWithPath from "../components/MapWithPath";
import "../style/FlightPage.css";
import apiClient from "../apiClient.jsx";

function FlightPage() {
    const location = useLocation();
    const [filters, setFilters] = useState(null);
    const [allFlights, setAllFlights] = useState([]);
    const [selectedFlights, setSelectedFlights] = useState([]);

    useEffect(() => {
        const searchData = location.state;
        if (searchData) {
            setFilters(searchData);
            fetchFlights(searchData);
        } else {
            setFilters(null);
            fetchFlights();
        }
    }, [location.state]);

    const fetchFlights = async (searchData = null) => {
        try {
            let uri = "api/flights";
            let params = {};

            if (searchData) {
                params = { 
                    tripType: searchData.tripType, 
                    departure: searchData.departure, 
                    arrival: searchData.arrival, 
                    date: searchData.date, 
                    returnDate: searchData.returnDate 
                };
                uri = searchData.tripType === "round" 
                    ? "api/flights/search/split"
                    : "api/flights/search";
            }

            const res = await apiClient.get(uri, { params });
            setAllFlights(res.data);
        } catch (error) {
            console.error("항공편 데이터 불러오기 실패", error);
            setAllFlights([]);
        }
    };

    const handleSearch = (searchData) => {
        setFilters(searchData);
        fetchFlights(searchData);
    };

    return (
        <div className="flight">
            <SearchFlight onSearch={handleSearch} />
            <div className="selected-flights-box">
                <MapWithPath flights={selectedFlights} />   
                <div className="flight-info-box">
                    <h3 className="mb-5">선택된 항공편</h3>
                    <div className="flight-pair-container1">
                        {selectedFlights.length === 2 ? (
                            <>
                                {selectedFlights[0] && selectedFlights[1] && (
                                    <>
                                        <div className="flight-card1">
                                            <p className="route1">
                                                ✈ {selectedFlights[0].departureName} → {selectedFlights[0].arrivalName}
                                            </p>
                                            <p className="date1">🗓 {selectedFlights[0].departureTime?.split("T")[0]}</p>
                                        </div>

                                        <div className="flight-card1">
                                            <p className="route1">
                                                ✈ {selectedFlights[1].departureName} → {selectedFlights[1].arrivalName}
                                            </p>
                                            <p className="date1">🗓 {selectedFlights[1].departureTime?.split("T")[0]}</p>
                                        </div>
                                    </>
                                )}
                            </>
                        ) : (
                            selectedFlights.length > 0 ? (
                                selectedFlights.map((flight, idx) => (
                                    flight ? (
                                        <div key={idx} className="flight-card1">
                                            <p className="route1">
                                                ✈ {flight.departureName} → {flight.arrivalName}
                                            </p>
                                            <p className="date1">🗓 {flight.departureTime?.split("T")[0]}</p>
                                        </div>
                                    ) : null
                                ))
                            ) : (
                                <p>선택된 항공편이 없습니다.</p>
                            )
                        )}
                    </div>
                </div>
            </div>
            <FlightList filters={filters} allFlights={allFlights} onSelectedFlights={setSelectedFlights} />
        </div>
    );
}

export default FlightPage;
