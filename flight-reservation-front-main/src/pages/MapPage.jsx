import GoogleMapInternational from "../components/map/GoogleMap.jsx";
import Sidebar from "../components/map/SideBar.jsx";
import {useState} from "react";

const MapPage = () => {
    const [flights, setFlights] = useState([]);
    const [departure, setDeparture] = useState({ name: "인천", code: "ICN", lat: 37.46, lng: 126.44 });
    const [arrival, setArrival] = useState(null);

    return (
        <div style={{ overflow: "hidden" }}>
            <div style={{
                display: "flex",
                height: "100vh",
                overflow: "hidden"
            }}>
                <div style={{ flex: 3 }}>
                    <GoogleMapInternational  departure={departure}
                                             arrival={arrival}
                                             setDeparture={setDeparture}
                                             setArrival={setArrival} />
                </div>
                <div style={{ flex: 1, overflowY: "auto", maxHeight: "100%" }}>
                    <Sidebar departure={departure}
                             arrival={arrival}
                             setDeparture={setDeparture}
                             setArrival={setArrival}
                             flights={flights}
                             setFlights={setFlights}/>
                </div>
            </div>
        </div>
    );
};


export default MapPage;
