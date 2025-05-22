import { createSlice } from '@reduxjs/toolkit';

const initialState = {
    isLoggedIn: false,
    email: null,
    accessToken: null,
    user: null,
};

const authSlice = createSlice({
    name: 'auth',
    initialState,
    reducers: {
        login: (state, action) => {
            const { email, accessToken, user } = action.payload;

            state.isLoggedIn = true;
            state.email = email;
            state.accessToken = accessToken;
            state.user = user;

            localStorage.setItem("accessToken", accessToken);
            localStorage.setItem("email", email);
            localStorage.setItem("user", JSON.stringify(user));
        },
        logout: (state) => {
            state.isLoggedIn = false;
            state.email = null;
            state.accessToken = null;
            state.user = null;

            localStorage.removeItem("accessToken");
            localStorage.removeItem("email");
            localStorage.removeItem("user");
        },
    },
});

export const { login, logout } = authSlice.actions;
export default authSlice.reducer;