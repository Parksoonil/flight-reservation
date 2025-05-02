// FlightManagement.js
import React, { useState, useEffect } from 'react';
import apiClient from '../apiClient';
import "../style/FlightManagement.css";

const FlightManagement = () => {
    const [flights, setFlights] = useState([]);
    const [airports, setAirports] = useState([]);
    const [aircraftModels, setAircraftModels] = useState([]);
    const [flightForm, setFlightForm] = useState(null);

    // 기본 폼 데이터
    const defaultFlight = {
        departureName: "",
        arrivalName: "",
        departureTime: "",
        arrivalTime: "",
        aircraftType: "",
        seatCount: "",
        flightClass: ""
    };

    // 모든 항공권 목록 가져오기
    useEffect(() => {
        apiClient
            .get('api/admin/flights')
            .then((response) => {
                console.log(response.data)
                setFlights(response.data);
            })
            .catch((error) => {
                console.error("Error fetching flights:", error);
            });
    }, []);

    // 공항 리스트 가져오기
    useEffect(() => {
        apiClient
            .get('api/admin/flights/airports')
            .then((response) => {
                console.log(response.data)
                setAirports(response.data);
            })
            .catch((error) => {
                console.error("Error fetching airports:", error);
            });
    }, []);

    // 항공기 모델 리스트 가져오기
    useEffect(() => {
        apiClient
            .get('api/admin/flights/aircraft')
            .then((response) => {
                console.log(response.data)
                setAircraftModels(response.data);
            })
            .catch((error) => {
                console.error("Error fetching aircraft models:", error);
            });
    }, []);

    // 날짜 포맷 변환 (YYYY-MM-DD HH:mm)
    const formatDateTime = (dateStr) => {
        if (!dateStr) return "";
        const date = new Date(dateStr);
        return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
    };

    // 항공권 생성 버튼 클릭 시 폼 표시
    const handleCreateClick = () => {
        setFlightForm({ ...defaultFlight });
    };

    // 항공권 수정 버튼 클릭 시 폼에 데이터 채우기
    const handleEditClick = (flight) => {
        setFlightForm({
            ...flight,
            departureTime: flight.departureTime ? new Date(flight.departureTime).toISOString().slice(0, 16) : "",
            arrivalTime: flight.arrivalTime ? new Date(flight.arrivalTime).toISOString().slice(0, 16) : "",
            departureId: flight.departureName,
            arrivalId: flight.arrivalName,
            aircraftId: flight.aircraftType
        });
    };

    // 항공권 삭제 버튼 클릭 시 삭제 후 목록 갱신
    const handleDeleteClick = (id) => {
        if (window.confirm("정말 삭제하시겠습니까?")) {
            apiClient
                .delete(`api/admin/flights/${id}`)
                .then(() => {
                    setFlights((prevFlights) => prevFlights.filter((f) => f.id !== id));
                })
                .catch((error) => {
                    console.error("Error deleting flight:", error);
                });
        }
    };

    // 폼 입력값 변경 처리
    const handleFormChange = (e) => {
        const { name, value } = e.target;
        setFlightForm((prevForm) => ({
            ...prevForm,
            [name]: value
        }));
    };

    // 항공권 생성 및 수정
    const handleFormSubmit = (e) => {
        e.preventDefault();
        const apiUrl = flightForm.id ? `api/admin/flights/${flightForm.id}` : `api/admin/flights`;

        apiClient[flightForm.id ? 'put' : 'post'](apiUrl, flightForm)
            .then((response) => {
                setFlights(flightForm.id
                    ? flights.map((f) => (f.id === flightForm.id ? response.data : f))
                    : [...flights, response.data]
                );
                setFlightForm(null);
            })
            .catch((error) => {
                console.error(`Error ${flightForm.id ? 'updating' : 'creating'} flight:`, error);
                alert(`항공권 ${flightForm.id ? '수정' : '생성'} 중 오류가 발생했습니다.`);
            });
    };

    return (
        <div className="flight-management">
            <h1 className="flight-management__title">항공권 관리</h1>
            <button onClick={handleCreateClick} className="flight-management__create-btn">
                항공권 생성
            </button>

            {/* 항공권 수정 폼 (편집 창) */}
            {flightForm && (
                <form className="flight-management__edit-form" onSubmit={handleFormSubmit}>
                    <h2>{flightForm.id ? "항공권 수정" : "항공권 생성"}</h2>

                    <div className="flight-management__form-group">
                        <label>출발 공항</label>
                        <select name="departureName" value={flightForm.departureName} onChange={handleFormChange} required>
                            <option value="">선택하세요</option>
                            {airports.map((airport) => (
                                <option key={airport.id} value={airport.anameKor}>
                                    {airport.anameKor} ({airport.acode})
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="flight-management__form-group">
                        <label>도착 공항</label>
                        <select name="arrivalName" value={flightForm.arrivalName} onChange={handleFormChange} required>
                            <option value="">선택하세요</option>
                            {airports.map((airport) => (
                                <option key={airport.id} value={airport.anameKor}>
                                    {airport.anameKor} ({airport.acode})
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="flight-management__form-group">
                        <label>출발 시간</label>
                        <input type="datetime-local" name="departureTime" value={flightForm.departureTime} onChange={handleFormChange} required />
                    </div>

                    <div className="flight-management__form-group">
                        <label>도착 시간</label>
                        <input type="datetime-local" name="arrivalTime" value={flightForm.arrivalTime} onChange={handleFormChange} required />
                    </div>

                    <div className="flight-management__form-group">
                        <label>항공기 모델</label>
                        <select name="aircraftType" value={flightForm.aircraftType} onChange={handleFormChange} required>
                            <option value="">선택하세요</option>
                            {aircraftModels.map((aircraft) => (
                                <option key={aircraft.id} value={aircraft.cmodel}>
                                    {aircraft.cmodel} ({aircraft.cname})
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="flight-management__form-group">
                        <label>좌석 수</label>
                        <input type="number" name="seatCount" value={flightForm.seatCount} onChange={handleFormChange} required />
                    </div>

                    <div className="flight-management__form-group">
                        <label>항공 클래스</label>
                        <input type="text" name="flightClass" value={flightForm.flightClass} onChange={handleFormChange} required />
                    </div>

                    <div className="flight-management__form-buttons">
                        <button type="submit" className="flight-management__update-btn">
                            {flightForm.id ? "수정" : "생성"}
                        </button>
                        <button type="button" onClick={() => setFlightForm(null)} className="flight-management__cancel-btn">
                            취소
                        </button>
                    </div>
                </form>
            )}

            {/* 항공권 목록 테이블 */}
            <table className="flight-management__table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>출발 공항</th>
                    <th>도착 공항</th>
                    <th>출발 시간</th>
                    <th>도착 시간</th>
                    <th>항공기 모델</th>
                    <th>좌석 수</th>
                    <th>항공 클래스</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {flights.map((flight) => (
                    <tr key={flight.id}>
                        <td>{flight.id}</td>
                        <td>{flight.departureName}</td>
                        <td>{flight.arrivalName}</td>
                        <td>{formatDateTime(flight.departureTime)}</td>
                        <td>{formatDateTime(flight.arrivalTime)}</td>
                        <td>{flight.aircraftType}</td>
                        <td>{flight.seatCount}</td>
                        <td>{flight.flightClass}</td>
                        <td>
                            <button onClick={() => handleEditClick(flight)}>수정</button>
                            <button onClick={() => handleDeleteClick(flight.id)}>삭제</button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
};

export default FlightManagement;
