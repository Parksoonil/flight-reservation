import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  flight: null,
  selectedSeats: [],
  contact: '',
  request: '',
};

const reservationSlice = createSlice({
  name: 'reservation',
  initialState,
  reducers: {
    setFlight: (state, action) => {
      state.flight = action.payload;
    },
    setSelectedSeats: (state, action) => {
      state.selectedSeats = action.payload;
    },
    setContact: (state, action) => {
      state.contact = action.payload;
    },
    setRequest: (state, action) => {
      state.request = action.payload;
    },
  },
});

export const { setFlight, setSelectedSeats, setContact, setRequest } = reservationSlice.actions;
export default reservationSlice.reducer;
