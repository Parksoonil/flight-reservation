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
import AdminPage from "./pages/AdminPage.jsx"
import Home1 from "./pages/Home1.jsx";
import FindAccount from "./pages/FindAccount.jsx";
import ReservationComplete from "./pages/ReservationComplete.jsx"

import {login, logout} from "./store/authSlice.js";
import {useDispatch, useSelector} from "react-redux";
import {useEffect} from "react";
import {jwtDecode} from "jwt-decode";
import apiClient from "./apiClient.jsx";
import ProtectedRoute from "./ProtectedRoute.jsx";
import PublicRoute from "./store/PublicRoute.jsx";
import EditProfile from "./pages/EditProfile.jsx";


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
        const expTime = decoded.exp * 1000; // 밀리초 단위로 변환
        if (Date.now() < expTime) {
          dispatch(login({ email: decoded.sub, accessToken: token, user: decoded }));
        } else {
          // 토큰 만료: refresh 요청을 직접 호출하여 새로운 토큰을 받아옵니다.
          apiClient.post(
                  "/api/users/refresh",
                  {},
                  { withCredentials: true }
              )
              .then((response) => {
                const { accessToken: newAccessToken } = response.data;
                localStorage.setItem("accessToken", newAccessToken);
                const newDecoded = jwtDecode(newAccessToken);
                dispatch(login({ email: newDecoded.sub, accessToken: newAccessToken, user: newDecoded }));
              })
              .catch((error) => {
                console.error("토큰 재발급 실패", error);
                dispatch(logout());
              });
        }
      } catch (error) {
        console.error("토큰 디코딩 실패", error);
      }
    }
  }, [dispatch]);

  // Redux store에서 인증정보 가져오기
  const { isLoggedIn, user } = useSelector((state) => state.auth);

  // 로그인 여부 확인
  const isAuthenticated = isLoggedIn;

  // user.admin이 true일 경우 관리자로 간주합니다.
  const isAdmin = user && user.admin === true;
  return (
    <div>
      {!hideLayout && <Header />}
      <div className="wrap">
        <ScrollTop />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login"
              element={
                <PublicRoute>
                  <Login />
                </PublicRoute>
              }/>
          <Route path="/findAccount"
              element={
                <PublicRoute>
                  <FindAccount />
                </PublicRoute>
              }/>
          <Route path="/signup"
              element={
                <PublicRoute>
                  <Signup />
                </PublicRoute>
              }/>
          <Route path="/editProfile" element={<EditProfile />} />
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
          <Route path="complete" element={<ReservationComplete/>} />
          <Route
              path="/admin"
              element={
                <ProtectedRoute isAuthenticated={isAuthenticated} isAdmin={isAdmin}>
                  <AdminPage />
                </ProtectedRoute>
              }
          />
        </Routes>
      </div>

      {!hideLayout && <Footer />}
    </div>
  );
}

export default App;
