import React from 'react';
import StepProgressBar from '../components/StepProgressBar';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import './ReservationLayout.css';

function ReservationLayout() {
  const steps = ['정보 확인', '좌석 선택', '추가정보 입력', '결제', '최종 확인'];
  const location = useLocation();
  const navigate = useNavigate();

  const getStepFromPath = (pathname) => {
    if (pathname.includes('/flight/')) return 0;
    if (pathname.includes('/rsv/seat')) return 1;
    if (pathname.includes('/rsv/detail')) return 2;
    if (pathname.includes('/rsv/payment')) return 3;
    if (pathname.includes('/rsv/result')) return 4;
    return 0;
  };

  const currentStep = getStepFromPath(location.pathname);

  const handleList = () => {
    navigate("/flight");
  };

  return (
    <div className="reservation-layout">
      <h1>항공편 예매</h1>
      <div className="reservation-content">
      <StepProgressBar steps={steps} currentStep={currentStep} />
        <Outlet />
      <div className='button-group'>
        <button className="back-button" onClick={handleList}>목록으로</button>
      </div>
      </div>
    </div>
  );
}

export default ReservationLayout;
