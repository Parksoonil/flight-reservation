import React, { useEffect, useState } from "react";
import "../style/WeatherForecast.css";

const WeatherForecast = () => {
  const [forecast, setForecast] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [regId, setRegId] = useState("11B00000");
  const [selectedRegion, setSelectedRegion] = useState("서울");

  const getWeatherIcon = (text) => {
    if (!text) return "❓";
    if (text.includes("맑음")) return "☀️";
    if (text.includes("구름") || text.includes("흐림")) return "☁️";
    if (text.includes("비")) return "🌧️";
    if (text.includes("눈")) return "❄️";
    return "🌈";
  };

  useEffect(() => {
    const fetchForecast = async () => {
      try {
        const today = new Date();
        const nowDate =
          today.toISOString().slice(0, 10).replace(/-/g, "") + "0600";
        const API_KEY = import.meta.env.VITE_API_KEY_a;
        const API_URL = `https://apis.data.go.kr/1360000/MidFcstInfoService/getMidLandFcst?serviceKey=${API_KEY}&pageNo=1&numOfRows=10&dataType=JSON&regId=${regId}&tmFc=${nowDate}`;
        const response = await fetch(API_URL);
        const data = await response.json();
        const item = data.response.body.items.item[0];
        setForecast(item);
      } catch (err) {
        setError("데이터를 불러오는 데 실패했습니다.");
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    if (regId !== "?") {
      setLoading(true);
      fetchForecast();
    }
  }, [regId]);

  const days = [4, 5, 6, 7];
  const nextDays = [8, 9, 10];

  const getDateLabel = (offset) => {
    const date = new Date();
    date.setDate(date.getDate() + offset);
    const weekdays = ["일", "월", "화", "수", "목", "금", "토"];
    return `${date.getMonth() + 1}월 ${date.getDate()}일 (${weekdays[date.getDay()]
      })`;
  };

  const regionCodes = {
    "서울": "11B00000",
    "강원": "11D10000",
    "충청": "11C20000",
    "호남": "11F20000",
    "경북": "11H10000",
    "경남": "11H20000",
    "제주": "11G00000"
  };

  const handleRegionClick = (region, code) => {
    setSelectedRegion(region);
    setRegId(code);
  };

  return (
    <div>
      <h1>날씨 예보</h1>
      <div className="weather-container">
        <div className="region-selection">
          {Object.keys(regionCodes).map((region) => (
            <button
              key={region}
              onClick={() => handleRegionClick(region, regionCodes[region])}
              className={selectedRegion === region ? "selected" : ""}
            >
              {region}
            </button>
          ))}
        </div>
        {loading ? (
          <div>⏳ 날씨 데이터를 불러오는 중...</div>
        ) : error ? (
          <div>❌ {error}</div>
        ) : !forecast ? null : (
          <>
            <div className="weather-cards-wrapper">
              <div className="weather-cards">
                {days.map((day) => (
                  <div key={`day${day}`} className="weather-card">
                    <h3>{getDateLabel(day)}</h3>
                    <div className="weather-icon">
                      {getWeatherIcon(forecast[`wf${day}Am`])}
                    </div>
                    <div className="weather-desc">
                      오전: {forecast[`wf${day}Am`]}
                    </div>
                    <div className="rain-prob">
                      💧 강수확률: {forecast[`rnSt${day}Am`]}%
                    </div>
                    <div className="weather-icon">
                      {getWeatherIcon(forecast[`wf${day}Pm`])}
                    </div>
                    <div className="weather-desc">
                      오후: {forecast[`wf${day}Pm`]}
                    </div>
                    <div className="rain-prob">
                      💧 강수확률: {forecast[`rnSt${day}Pm`]}%
                    </div>
                  </div>
                ))}

                {nextDays.map((day) => (
                  <div key={`day${day}`} className="weather-card">
                    <h3>{getDateLabel(day)}</h3>
                    <div className="weather-icon">
                      {getWeatherIcon(forecast[`wf${day}`])}
                    </div>
                    <div className="weather-desc">
                      날씨: {forecast[`wf${day}`]}
                    </div>
                    <div className="rain-prob">
                      💧 강수확률: {forecast[`rnSt${day}`]}%
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
      <p style={{ textAlign: "right", fontSize: "12px", color: "gray" }}>
        ※ 본 서비스는{" "}
        <a
          href="https://www.data.go.kr"
          target="_blank"
          rel="noopener noreferrer"
        >
          공공데이터포털(www.data.go.kr)
        </a>
        의 [기상청_중기예보 조회서비스]를 활용하여 제공됩니다.
      </p>
    </div>
  );
};

export default WeatherForecast;
