import { useState } from "react";
import { AirpostList } from "../data/airpostList.jsx"; // 공항 목록 배열
import "../style/AirportSelectDropdown.css";

const AirportSelectDropdown = ({ onSelect, onClose }) => {
    const [searchTerm, setSearchTerm] = useState("");

    const filteredAirports = AirpostList.filter(
        (airport) =>
            airport.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            airport.code.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="airport-dropdown">
            <input
                type="text"
                className="airport-search-input"
                placeholder="도시 또는 코드 검색"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
            />
            <ul className="airport-list">
                {filteredAirports.map((airport) => (
                    <li key={airport.code}>
                        <button
                            onClick={() => {
                                onSelect(airport.name); // 필요 시 airport.code도 같이 전달 가능
                                onClose();
                            }}
                        >
                            {airport.name} ({airport.code})
                        </button>
                    </li>
                ))}
                {filteredAirports.length === 0 && (
                    <li className="no-result">검색 결과 없음</li>
                )}
            </ul>
        </div>
    );
};

export default AirportSelectDropdown;
