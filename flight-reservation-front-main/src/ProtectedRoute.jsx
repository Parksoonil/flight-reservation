// ProtectedRoute.jsx
import React from 'react';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ isAuthenticated, isAdmin, children }) => {
    // 인증되지 않은 경우 로그인 페이지로 이동합니다.
    if (!isAuthenticated) {
        return <Navigate to="/login" />;
    }

    // 인증은 되었지만 관리자가 아니라면 홈 페이지로 이동합니다.
    if (!isAdmin) {
        return <Navigate to="/" />;
    }

    return children;
};

export default ProtectedRoute;
