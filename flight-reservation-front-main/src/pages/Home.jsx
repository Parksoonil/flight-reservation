import SearchFlight from "../components/SearchFlight";
import AdBanner from "../components/AdBanner";

import "../style/Home.css";
import QuickLink from "../components/QuickLink";
import Hotplace from "../components/Hotplace";
import SimpleAirportMap from "../components/SimpleAirportMap";
import WeatherForecast from "../components/WeatherForecast";
import Boards from "../components/Boards";

function Home() {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="home">
      <div className="banner">
        <img src="/images/img1.jpg" alt="Banner Image" />
      </div>

      <div className="contents-box">
        <SearchFlight />
        <QuickLink />
        <SimpleAirportMap />
        <AdBanner />
        <Hotplace />
        <WeatherForecast />
        <Boards />
      </div>
      <div className="scroll-to-top" onClick={scrollToTop}>
      <p>↑ 페이지 상단으로 이동</p>
      </div>
    </div>
  );
}

export default Home;
