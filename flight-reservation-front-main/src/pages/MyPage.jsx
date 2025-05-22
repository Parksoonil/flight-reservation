import { useDispatch, useSelector } from "react-redux";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import EditProfileForm from "../components/myPage/EditProfileForm.jsx";
import DeleteAccountForm from "../components/myPage/DeleteAccountForm.jsx";
import UserSummary from "../components/myPage/UserSummary.jsx";
import ReservationList from "../components/myPage/ReservationList.jsx";
import apiClient from "../apiClient.jsx";
import { logout } from "../store/authSlice.js";

import "../styles/Mypage.css"

function MyPage() {
  const dispatch = useDispatch();
  const { accessToken } = useSelector((state) => state.auth);
  const currentUserEmail = useSelector((state) => state.auth.email);
  const [user, setUser] = useState(null);
  const [selectedMenu, setSelectedMenu] = useState("summary");
  const navigate = useNavigate();

  useEffect(() => {
    if (!accessToken) {
      navigate("/login");
      return;
    }

    let userid;
    try {
      const decoded = jwtDecode(accessToken);
      userid = decoded.userid;
    } catch (error) {
      console.error("토큰 디코딩 실패:", error);
      navigate("/login");
      return;
    }

    (async () => {
      try {
        const { data: userDataRaw } = await apiClient.get(`api/users/id/${userid}`);
        const userData = Array.isArray(userDataRaw) ? userDataRaw[0] : userDataRaw;
        setUser(userData);

      } catch (error) {
        console.error("데이터 로딩 실패:", error);
      }
    })();
  }, [accessToken, navigate]);

  const handleSaveProfile = async (updatedUser) => {
    try {
      await apiClient.put(`api/users/${updatedUser.id}`, updatedUser);
      setUser(updatedUser);
      alert("내정보가 성공적으로 업데이트되었습니다.");
      setIsEditing(false);
      window.location.reload();
    } catch (error) {
      alert("내정보 업데이트 중 문제가 발생했습니다." + error);
    }
  };

  const handleConfirmDelete = async (inputEmail) => {
    if (inputEmail.trim().toLowerCase() !== currentUserEmail.toLowerCase()) {
      alert("이메일 확인 실패");
      return;
    }

    try {
      const config = {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        withCredentials: true, // 만약 백엔드가 refreshToken을 쿠키로 관리하는 경우 필요
      };

      await apiClient.delete(`http://localhost:8443/api/users/${user.id}`, config);
      await apiClient.post(`http://localhost:8443/api/users/logout`, {}, config);
      dispatch(logout());

      alert("회원 탈퇴 완료");
      navigate("/login");
    } catch (error) {
      console.error("회원 탈퇴 실패:", error.response || error);
      alert("회원 탈퇴 실패");
    }
  };

  const handleMenuChange = (menu) => {
    setSelectedMenu(menu);
    setIsEditing(false);
    setIsDeleting(false);
  };

  const renderContent = () => {
    if (!user) return <p>Loading...</p>;

    switch (selectedMenu) {
      case "summary":
        return <UserSummary user={user} userId={user.id} />;
      case "user":
        return (
          <EditProfileForm
            user={user}
            onCancel={() => setSelectedMenu("summary")}
            onSave={handleSaveProfile}
          />
        );
      case "delete":
        return (
          <DeleteAccountForm
            userEmail={currentUserEmail}
            onCancel={() => setSelectedMenu("summary")}
            onConfirm={handleConfirmDelete}
          />
        );
      case "reservations":
        return <ReservationList userId={user.id} />;
      default:
        return null;
    }
  };

  return (
    <div className={`my-page-container ${selectedMenu}`}>
      <div className="sidebar">
        <ul>
          <li className={`menu-item-wrapper ${selectedMenu === "summary" ? "active summary" : ""}`}>
            <button onClick={() => handleMenuChange("summary")} className={`summary-border ${selectedMenu === "summary" ? "active" : ""}`}>
              마이페이지
            </button>
          </li>
          <li className={`menu-item-wrapper ${selectedMenu === "reservations" ? "active reservations" : ""}`}>
            <button onClick={() => handleMenuChange("reservations")} className={`reservations-border ${selectedMenu === "reservations" ? "active" : ""}`}>
              예매 내역
            </button>
          </li>
          <li className={`menu-item-wrapper ${selectedMenu === "user" ? "active user" : ""}`}>
            <button onClick={() => handleMenuChange("user")} className={`user-border ${selectedMenu === "user" ? "active" : ""}`}>
              회원 정보 수정
            </button>
          </li>
        </ul>
        <ul className="bottom-menu-list">
          <li className={`menu-item-wrapper ${selectedMenu === "delete" ? "active delete" : ""}`}>
            <button onClick={() => handleMenuChange("delete")} className={`delete-border ${selectedMenu === "delete" ? "active" : ""}`}>
              회원 탈퇴
            </button>
          </li>
        </ul>
      </div>

      <div className={`content-wrapper ${selectedMenu}`}>
        <div className={`content ${selectedMenu}-border`}>
          {renderContent()}
        </div>
      </div>
    </div>
  );
}

export default MyPage;
