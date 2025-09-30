// server/index.js
// Simple WebSocket server that emits simulated packet alerts every few seconds.
// Run: node server/index.js

const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 8080 });
console.log("WebSocket server listening on ws://localhost:8080");

function randomIP() {
  return `${Math.floor(Math.random()*223)+1}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`;
}

function randomPayload() {
  const samples = [
    "GET /index.html HTTP/1.1",
    "USER admin\r\nPASS password123",
    "POST /login HTTP/1.1\r\nusername=alice&password=secret",
    "Normal DNS query for example.com",
    "Suspicious cmd.exe usage: cmd.exe /c net user",
    "TLS Client Hello - ja3: 769,0-11-23"
  ];
  return samples[Math.floor(Math.random()*samples.length)];
}

function createAlert() {
  const payload = randomPayload();
  const src = randomIP();
  const dst = randomIP();
  const severity = Math.random() < 0.2 ? "high" : Math.random() < 0.4 ? "medium" : "low";
  return {
    id: Date.now().toString(36) + Math.floor(Math.random()*1000),
    time: new Date().toISOString(),
    src, dst,
    protocol: Math.random() < 0.5 ? "TCP" : "UDP",
    src_port: Math.floor(Math.random()*65535),
    dst_port: [80,443,22,53,8080][Math.floor(Math.random()*5)],
    severity,
    reason: severity === "high" ? "Known bad payload pattern" : severity === "medium" ? "Anomalous flow" : "Suspicious header",
    payload_preview: payload,
    raw_hex: Buffer.from(payload).toString('hex')
  };
}

wss.on('connection', (ws) => {
  console.log("Client connected");
  const sendInterval = setInterval(() => {
    const alert = createAlert();
    ws.send(JSON.stringify({ type: "alert", data: alert }));
  }, 1500 + Math.random()*2000);

  ws.on('close', () => {
    clearInterval(sendInterval);
    console.log("Client disconnected");
  });

  ws.on('message', (msg) => {
    // allow client to request a pcap export or ack
    try {
      const m = JSON.parse(msg.toString());
      if (m.type === 'ack') {
        console.log("Client ack:", m.id);
      }
    } catch (e) {}
  });
});
