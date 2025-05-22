import {Outlet, useLocation } from "react-router-dom";
import StepProgressBar from "../components/StepProgressBar.jsx";

import "./ReservationLayout.css"


function ReservationLayout() {
    const steps = ['정보 확인', '좌석 선택', '추가정보 입력', '최종 확인', '완료'];
    const location = useLocation();

    const getStepFromPath = (pathname) => {
        if (pathname.includes('/flight/')) return 0;         // 정보 확인
        if (pathname.includes('/select/')) return 1;         // 좌석 선택
        if (pathname.includes('/form/')) return 2;           // 추가정보 입력
        if (pathname.includes('/confirm/')) return 3;        // 최종 확인
        if (pathname.includes('/complete')) return 4;        // 완료
        return 0;
    };

    const currentStep = getStepFromPath(location.pathname);

    return (
        <div className="reservation-layout">
            <h1>항공편 예매</h1>
            <div className="reservation-content">
                <StepProgressBar steps={steps} currentStep={currentStep} />
                <Outlet />
            </div>
        </div>
    );
}

export default ReservationLayout;
