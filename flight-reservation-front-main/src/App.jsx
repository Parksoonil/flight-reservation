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


function App() {
  const location = useLocation();
  const hideLayoutRoutes = ["/login", "/signup", "/payment"];
  const hideLayout = hideLayoutRoutes.includes(location.pathname);


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

          <Route element={<ReservationLayout />}>
            <Route path="/flight/detail" element={<FlightDetail />} />
            <Route path="/rsv/seat" element={<SelectSeat />} />
            <Route path="/rsv/detail" element={<RSVDetail />} />
            <Route path="/rsv/payment" element={<RSVPayment />} />
            <Route path="/rsv/result" element={<RSVResult />} />
          </Route>
        </Routes>
      </div>

      {!hideLayout && <Footer />}
    </div>
  );
}

export default App;
