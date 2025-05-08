import { useState } from "react";
import { allAirports } from "../data/allAirports.js";
import "../style/dd.css"

const AirportSelectModal = ({ onClose, onSelect }) => {
    const [query, setQuery] = useState("");

    const filtered = allAirports.filter(a =>
        a.name.includes(query) || a.code.includes(query.toUpperCase())
    );

    return (
        <div className="popup-overlay">
            <div className="popup-box">
                <div className="popup-header">
                    <span>공항 선택</span>
                    <button onClick={onClose}>✕</button>
                </div>
                <input
                    type="text"
                    placeholder="공항명 또는 코드 검색"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    style={{ width: "100%", marginBottom: "10px", padding: "6px" }}
                />
                <div className="popup-list" style={{ maxHeight: "300px", overflowY: "auto" }}>
                    {filtered.map((airport) => (
                        <div
                            key={airport.code}
                            onClick={() => {
                                onSelect(airport);
                                onClose();
                            }}
                            style={{ padding: "8px", cursor: "pointer" }}
                        >
                            {airport.name} ({airport.code})
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default AirportSelectModal;
