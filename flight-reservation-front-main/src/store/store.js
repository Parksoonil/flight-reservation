import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./authSlice";

const store = configureStore({
    reducer: {
        auth: authReducer, // auth 슬라이스가 key 'auth'로 등록되어야 합니다.
    },
});

export default store;

