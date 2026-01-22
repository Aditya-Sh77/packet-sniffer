Node version[https://github.com/Aditya-Sh77/Packet-Capture]
# Packet Sniffer

A full-stack packet sniffer and alert dashboard. The backend captures packets, inspects them for suspicious activity, and streams alerts to a modern React frontend via WebSocket.

## Features
- Live packet capture and inspection (Python backend with Scapy)
- WebSocket server for real-time alert streaming
- React + Tailwind CSS frontend for alert display and filtering
- Wireshark-like search and filtering (by IP, port, protocol, severity, etc.)
- Payload preview with safe handling for encrypted/binary data
- Acknowledge and copy alert details

## Getting Started

### Prerequisites
- Python 3.8+
- Node.js 16+

### Backend Setup
1. Install Python dependencies:
   ```sh
   pip install scapy websockets
   ```
2. Run the backend server (as root/admin for live capture):
   ```sh
   python server/server.py
   ```
   - Use `--iface` for live capture or `--pcap` to replay a pcap file.

### Frontend Setup
1. Install frontend dependencies:
   ```sh
   cd ui/frontend
   npm install
   ```
2. Start the frontend dev server:
   ```sh
   npm run dev
   ```
3. Open [http://localhost:5173](http://localhost:5173) in your browser.

## Usage
- Alerts will appear in the sidebar as packets are captured.
- Use the search bar to filter alerts (e.g., `src:192.168 port:443 severity:high`).
- Click an alert to view details, preview payload, and acknowledge or copy JSON.

## Project Structure
```
server/         # Python backend (packet sniffer, WebSocket server)
ui/frontend/    # React frontend (dashboard UI)
```

## Security & Notes
- Live capture requires root/admin privileges.
- Only use on networks you own or have permission to monitor.

## License
MIT
