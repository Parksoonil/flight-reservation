# Flight Reservation System

## 개요
**Flight Reservation System**은 MSA(Microservices Architecture)를 채택하여 항공편 검색, 예약, 유저 관리 등 다양한 서비스를 분산된 마이크로서비스로 구현한 애플리케이션입니다. 개별 서비스는 확장성과 유지보수에 용이하도록 구성되었으며, Eureka를 통한 서비스 디스커버리와 Gateway를 통한 API 라우팅을 지원합니다.

## 아키텍처 개요
프로젝트는 아래와 같은 주요 컴포넌트로 구성됩니다:

- **Eureka (서비스 레지스트리)**
  - 포트: **8761**
  - 모든 마이크로서비스는 Eureka에 등록되어 서로의 위치를 자동으로 검색합니다.
  
- **Gateway (API 게이트웨이)**
  - 포트: **8443**
  - 클라이언트의 요청을 해당 서비스로 라우팅하며, 인증, 로깅 등 부가 기능을 처리합니다.
  
- **유저 서비스**
  - 포트: **8081**
  - 회원가입, 로그인, 프로필 관리 등 유저 관련 기능을 담당합니다.
  
- **항공 서비스**
  - 포트: **8082**
  - 항공편 정보 관리, 항공편 검색 및 상세 정보 제공 기능을 제공합니다.
  
- **예매 서비스**
  - 포트: **8083**
  - 항공편 예약 및 결제 처리, 예약 내역 관리 기능을 제공합니다.

## 주요 기능
- **항공편 검색**: 사용자가 입력한 출발지, 도착지, 날짜 정보를 기반으로 항공편 목록을 조회할 수 있습니다.
- **예약 처리**: 선택한 항공편에 대한 예약 및 결제 과정을 진행합니다.
- **예약 관리**: 예약 내역 조회, 수정, 취소 기능을 제공합니다.
- **유저 관리**: 회원가입, 로그인, 비밀번호 복구, 프로필 관리 등 사용자 관련 작업을 수행합니다.
- **위치 기반 서비스**: **카카오맵 오픈 API**를 활용하여 항공편 출발지 및 도착지 주변 위치를 시각화합니다.
- **날씨 정보 제공**: **날씨 오픈 API**를 통해 항공편 운항 및 예약에 참고할 수 있는 실시간 날씨 정보를 제공합니다.
- **RESTful API**: 각 서비스는 독립적인 REST API 엔드포인트를 제공하며, Gateway를 통해 통합된 API 사용이 가능합니다.

## 기술 스택
- **백엔드**:
  - **언어/프레임워크**: Java 17 이상, Spring Boot  
  - **빌드 도구**: Gradle  
  - **보조 기술**:
    - **Redis**: 세션 관리 및 캐시 처리  
    - **JWT**: 사용자 인증 및 토큰 기반 보안 처리  
    - **Elasticsearch**: 항공편 검색의 고속화 및 색인 최적화  
    - **Kafka**: 비동기 메시징 및 이벤트 스트리밍  
- **마이크로서비스 인프라**:
  - **Eureka**: 서비스 디스커버리 (포트 8761)  
  - **Gateway**: API 라우팅 및 부가 기능 (포트 8443)  
  - **유저 서비스**: (포트 8081)  
  - **항공 서비스**: (포트 8082)  
  - **예매 서비스**: (포트 8083)  
- **외부 API 통합**:
  - **카카오맵 오픈 API**: 지도 기반 위치 서비스 제공  
  - **날씨 오픈 API**: 실시간 날씨 정보 제공  
- **프론트엔드**: React + Vite  
  - **폴더명**: `flight-reservation-front-main`  
  - **개발 서버 포트**: 5173  
- **데이터베이스**: MySQL 또는 PostgreSQL

## 설치 및 실행 방법

### 전제 조건
- **Java 17 이상** 설치  
- **Gradle** (프로젝트 내 `gradlew` 스크립트 포함)  
- **Node.js 및 npm** (프론트엔드 실행용)  
- **데이터베이스 서버** (MySQL, PostgreSQL 등) 구동  

### 설치 단계

1. **레포지토리 클론**
   ```bash
   git clone https://github.com/Parksoonil/flight-reservation.git
   cd flight-reservation

# Flight Reservation 프로젝트

이 프로젝트는 백엔드(마이크로서비스)와 프론트엔드(React + Vite)로 구성되어 있으며, 각 마이크로서비스는 독립된 Gradle 모듈 또는 애플리케이션으로 구성되어 있습니다.


## 백엔드 (마이크로서비스) 빌드 및 실행

### 공통 빌드 (예시)
```bash
./gradlew build
```

### Eureka 서버 실행 (포트 8761)
```bash
./gradlew :eureka-server:bootRun
```

### Gateway 실행 (포트 8443)
```bash
./gradlew :gateway:bootRun
```

### 유저 서비스 실행 (포트 8081)
```bash
./gradlew :user-service:bootRun
```

### 항공 서비스 실행 (포트 8082)
```bash
./gradlew :flight-service:bootRun
```

### 예매 서비스 실행 (포트 8083)
```bash
./gradlew :reservation-service:bootRun
```

각 서비스 실행 후, [Eureka 대시보드](http://localhost:8761)에 접속하여 등록된 서비스 목록을 확인할 수 있습니다.

---

## 프론트엔드 실행 (React + Vite)

1. 프론트엔드 디렉토리로 이동:
   ```bash
   cd flight-reservation-front-main
   npm install
   ```
2. 개발 서버 실행:
   ```bash
   npm run dev
   ```
3. 브라우저에서 [http://localhost:5173](http://localhost:5173)으로 접속하여 프론트엔드 애플리케이션을 확인합니다.

---

## 사용 방법

- **웹 인터페이스**: 브라우저에서 Gateway 주소([https://localhost:8443](https://localhost:8443))를 통해 각 서비스 기능에 접근합니다.
- **API 사용**: 각 마이크로서비스는 독립적인 RESTful API를 제공하며, Swagger 또는 Postman을 통해 개별 API 엔드포인트를 테스트할 수 있습니다.
- **서비스 디스커버리**: Eureka 대시보드를 통해 현재 등록된 서비스 목록 및 상태를 확인할 수 있습니다.

---

## 프로젝트 팀 및 담당 분야

- **박순일**: 유저 서비스 담당 및 통합 담당
- **이용수**: 항공 서비스 담당 및 카카오맵 API 연동 담당
- **최민석**: 예매 서비스 담당, 결제 서비스 및 Kafka 통신 설계
- **박세호**: 프론트 엔드 총괄 및 디자인 담당, 날씨 API 연동 담당

---

## 기여 방법

1. 레포지토리를 fork합니다.
2. 새로운 브랜치를 생성합니다.
   ```bash
   git checkout -b feature/새로운기능
   ```
3. 변경 사항을 commit합니다.
4. 변경 사항을 push한 후, pull request를 생성합니다.
5. 문제 제보나 기능 요청은 Issue를 등록해 주시면 감사하겠습니다.

---

## 라이센스

이 프로젝트는 **MIT 라이센스** 하에 배포됩니다. 자세한 내용은 [`LICENSE`](LICENSE) 파일을 참조하세요.

---

## 문의 및 연락처

프로젝트 관련 문의는 [Parksoonil GitHub 프로필](https://github.com/parksoonil) 또는 이슈 트래커를 통해 연락해주시면 됩니다.
