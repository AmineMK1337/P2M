# ANDS Frontend Dashboard

React + Vite dashboard for visualizing the ANDS flow in real time:
Traffic -> Feature Extraction -> ML Detection -> Decision

## Stack

- React
- Tailwind CSS
- Recharts
- Framer Motion

## Run

```powershell
cd frontend
npm install
npm run dev
```

Default URL: http://localhost:5173

## API Integration

The UI polls these endpoints every 2 seconds:

- GET /api/traffic
- GET /api/features
- GET /api/predictions
- GET /api/decisions

Set a base API URL if Flask runs on another host/port:

```powershell
$env:VITE_API_BASE_URL = "http://127.0.0.1:5000"
npm run dev
```

If API requests fail, the dashboard automatically uses realistic mock data for demo mode.
