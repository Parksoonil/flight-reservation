import { Route, Routes, useLocation } from "react-router-dom";
import './App.css';

import Home from "./pages/Home";
import ScrollTop from "./components/ScrollTop";
import FlightPage from "./pages/FlightPage";
import FlightDetail from "./pages/FlightDetail";
import ReservationLayout from "./layout/ReservationLayout";
import SelectSeat from "./pages/SelectSeat";
import RSVDetail from "./pages/RSVDetail";
import Header from "./layout/Header";
import Footer from "./layout/Footer";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import MyPage from "./pages/Mypage";
import Payment from "./pages/Payment";
import RSVResult from "./pages/RSVResult";
import RSVPayment from "./pages/RSVPayment";
import BoardPage from "./pages/BoardPage";
import BoardWrite from "./pages/BoardWrite";
import RplacePage from "./pages/RplacePage";
import SplacePage from "./pages/SplacePage";
import BoardDetail from "./pages/BoardDetail";
import SeatInfoFormPage from "./pages/SeatInfoFormPage.jsx";
import SeatConfirmationPage from "./pages/SeatConfirmationPage.jsx";
import Home1 from "./pages/Home1.jsx";
import {login} from "./store/authSlice.js";
import {useDispatch} from "react-redux";
import {useEffect} from "react";
import {jwtDecode} from "jwt-decode";


function App() {
  const location = useLocation();
  const dispatch = useDispatch();
  const hideLayoutRoutes = ["/login", "/signup", "/payment"];
  const hideLayout = hideLayoutRoutes.includes(location.pathname);

  useEffect(() => {
    const token = localStorage.getItem("accessToken");
    if (token) {
      try {
        const decoded = jwtDecode(token);
        const expTime = decoded.exp * 1000;
        if (Date.now() < expTime) {
          // 만료되지 않은 토큰이라면 Redux 로그인 상태를 갱신합니다.
          // 여기서는 decoded 내의 정보를 적절하게 활용하여 login 액션을 dispatch 합니다.
          dispatch(login({ email: decoded.sub, accessToken: token, user: decoded }));
        } else {
          // 토큰이 만료된 경우 처리 (예: localStorage에서 삭제)
          localStorage.removeItem("accessToken");
        }
      } catch (error) {
        console.error("토큰 디코딩 실패", error);
      }
    }
  }, [dispatch]);
  return (
    <div>
      {!hideLayout && <Header />}
      <div className="wrap">
        <ScrollTop />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/flight" element={<FlightPage />} />
          <Route path="/mypage" element={<MyPage />} />
          <Route path="/payment" element={<Payment />} />
          <Route path="/board" element={<BoardPage />} />
          <Route path="/bwrite" element={<BoardWrite />} />
          <Route path="/board/:boardId" element={<BoardDetail />} />
          <Route path="/rplace" element={<RplacePage />} />
          <Route path="/splace" element={<SplacePage />} />
          <Route path="/loading" element={<Home1/>}/>
          <Route path="/select/:key" element={<SelectSeat/>}/>
          <Route path="/form/:key" element={<SeatInfoFormPage />} />
          <Route path="/confirm/:key" element={<SeatConfirmationPage />} />
        </Routes>
      </div>

      {!hideLayout && <Footer />}
    </div>
  );
}

export default App;
