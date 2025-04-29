import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../style/QuickLink.css";

function QuickLink() {
    const scrollRef = useRef(null);
    const [isDragging, setIsDragging] = useState(false);
    const [startX, setStartX] = useState(0);
    const [scrollStart, setScrollStart] = useState(0);
    const navigate = useNavigate();

    const data = [
        {
            id: 1,
            title: "항공권 검색",
            item: "원하는 항공편 검색하기",
            image: "✈️",
            link: "/flight"
        },
        {
            id: 2,
            title: "추천 관광지",
            item: "지역별 인기 관광지 확인하기",
            image: "🏞️",
            link: "/rplace"
        },
        {
            id: 3,
            title: "항공권 혜택",
            item: "특별 할인 혜택 확인하기",
            image: "🎁",
            link: "/board"
        },
        {
            id: 4,
            title: "1:1 문의",
            item: "고객 센터 바로가기",
            image: "🌟",
            link: "/"
        },
    ];

    const handleMouseDown = (e) => {
        setIsDragging(true);
        setStartX(e.pageX - scrollRef.current.offsetLeft);
        setScrollStart(scrollRef.current.scrollLeft);
        document.body.style.userSelect = "none";
    };

    const handleMouseUpOrLeave = () => {
        setIsDragging(false);
        document.body.style.userSelect = "auto";
    };

    const handleMouseMove = (e) => {
        if (!isDragging) return;
        e.preventDefault();
        const x = e.pageX - scrollRef.current.offsetLeft;
        const walk = (x - startX) * 1.0;
        scrollRef.current.scrollLeft = scrollStart - walk;
    };


    const handleCardClick = (link) => {
        navigate(link);
    };

    return (
        <div>
            <ul
                ref={scrollRef}
                className={`quicklink-scroll ${isDragging ? "dragging" : ""}`}
                onMouseDown={handleMouseDown}
                onMouseUp={handleMouseUpOrLeave}
                onMouseLeave={handleMouseUpOrLeave}
                onMouseMove={handleMouseMove}
            >
                {data.map((item) => (
                    <li key={item.id} onClick={() => handleCardClick(item.link)} className="quicklink-item">
                        <div className="quicklink-text">
                            <h3>{item.title}</h3>
                            <p>{item.item}</p>
                        </div>
                        <div className="quicklink-image-placeholder">
                            <p>{item.image}</p>
                        </div>
                    </li>
                ))}
            </ul>
        </div>
    );
}

export default QuickLink;
