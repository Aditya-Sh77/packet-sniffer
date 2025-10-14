import  { useEffect, useRef, useState } from "react";

type Alert = {
  id: string;
  time: string;
  src: string;
  dst: string;
  protocol: string;
  src_port: number;
  dst_port: number;
  severity: "low" | "medium" | "high";
  reason: string;
  payload_preview: string;
  payload_label: string; // e.g. "TLS/ENCRYPTED", "EMPTY", "ASCII", "BINARY"
  payload_ascii: string;
  raw_hex: string;
};

function severityColor(s: Alert["severity"]) {
  if (s === "high") return "bg-red-500";
  if (s === "medium") return "bg-yellow-500";
  return "bg-emerald-400";
}
export default function App() {
  const alertsRef = useRef<Alert[]>([]);
  const [capture, setCapture] = useState(false);
  const captureRef = useRef(capture);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);



  // Keep captureRef in sync with capture state
  useEffect(() => {
    captureRef.current = capture;
  }, [capture]);

  // Keep alertsRef in sync with state
  useEffect(() => {
    alertsRef.current = alerts;
  }, [alerts]);

  useEffect(() => {
    let ws: WebSocket | null = null;

    const connectWS = (attempts = 5) => {
      ws = new WebSocket("ws://127.0.0.1:8080");
      wsRef.current = ws;

      ws.onopen = () => console.log("Connected to WS server ✅");

      ws.onmessage = (ev) => {
        if (captureRef.current) {
          const msg = JSON.parse(ev.data);
          console.log("Alert received:", msg);

          if (msg.type === "alert") {
            const newAlerts = [msg.data, ...alertsRef.current]; // always use the ref
            alertsRef.current = newAlerts;
            setAlerts(newAlerts);

            setSelected((prev) => (prev ? prev : msg.data)); // select first alert by default
          }
        }
      };

      ws.onerror = () => {
        if (attempts > 0) {
          console.log("WS connection failed, retrying...");
          setTimeout(() => connectWS(attempts - 1), 500);
        } else {
          console.error("WS connection failed permanently ❌");
        }
      };

      ws.onclose = () => console.log("WS closed");
    };

    connectWS();

    return () => ws?.close();
  }, []);



  // // Wireshark-like search filter
  // function matchesSearch(alert: Alert, query: string) {
  //   if (!query.trim()) return true;
  //   const terms = query.trim().split(/\s+/);
  //   return terms.every(term => {
  //     // field:value support
  //     const m = term.match(/^(src|dst|protocol|severity|port|id|reason):(.+)$/i);
  //     if (m) {
  //       const field = m[1].toLowerCase();
  //       const value = m[2].toLowerCase();
  //       if (field === "src") return alert.src.toLowerCase().includes(value);
  //       if (field === "dst") return alert.dst.toLowerCase().includes(value);
  //       if (field === "protocol") return alert.protocol.toLowerCase().includes(value);
  //       if (field === "severity") return alert.severity.toLowerCase().includes(value);
  //       if (field === "port") return (String(alert.src_port).includes(value) || String(alert.dst_port).includes(value));
  //       if (field === "id") return alert.id.toLowerCase().includes(value);
  //       if (field === "reason") return alert.reason.toLowerCase().includes(value);
  //       return false;
  //     }
  //     // General text search
  //     const v = term.toLowerCase();
  //     return (
  //       alert.src.toLowerCase().includes(v) ||
  //       alert.dst.toLowerCase().includes(v) ||
  //       alert.protocol.toLowerCase().includes(v) ||
  //       alert.severity.toLowerCase().includes(v) ||
  //       String(alert.src_port).includes(v) ||
  //       String(alert.dst_port).includes(v) ||
  //       alert.id.toLowerCase().includes(v) ||
  //       alert.reason.toLowerCase().includes(v)
  //     );
  //   });
  // }

  // const filteredAlerts = alerts.filter(al => matchesSearch(al, searchQuery));
  // console.log("Filtered alerts:", filteredAlerts, "Search query:", searchQuery);

  return (
    <div className="flex h-screen font-sans">
      {/* Sidebar */}
      <div className="w-[420px] border-r border-gray-200 p-4 flex flex-col">
        <h2 className="text-xl font-bold">Packet Alerts</h2>
        <section className="flex justify-center items-center">
          
          <button className="px-3 py-1 rounded-lg bg-gray-200 hover:bg-gray-300 text-sm mt-3 mb-3 mr-10  w-[30%]" 
          onClick={() => {setCapture(c => !c)}}>{capture ? "Stop Capture" : "Start Capture"}
          </button>
          
          <button className="px-3 py-1 rounded-lg bg-gray-200 hover:bg-gray-300 text-sm mt-3 mb-3 w-[30%]" onClick={() => {
            wsRef.current?.send(JSON.stringify({type: "clear"}));
            alertsRef.current = [];
            setAlerts([]);
            setSelected(null);
            console.log("Cleared alerts");
            console.log("Current alerts after clear:", alerts);
          }}>
            Clear alerts
          </button>

        </section>  
        <div className="text-gray-500 text-sm mb-3">
          Live stream — {alerts.length} alerts
        </div>
        {/* Wireshark-like search bar
        <div className="mb-3">
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="border rounded px-2 py-1 w-full text-xs"
            placeholder="Search (e.g. src:192.168 port:443 severity:high TCP)"
          />
        </div> */}
        <div className="overflow-y-auto flex-1 space-y-2" key={alerts.length}>
          {alerts.map((al) => (
            console.log("Rendering alert:", al),
            <div
              key={al.id}
              onClick={() => setSelected(al)}
              className="bg-white rounded-xl p-3 shadow-sm cursor-pointer hover:shadow-md flex justify-between items-center"
            >
              <div>
                <div className="font-semibold text-gray-800">
                  {al.src}:{al.src_port} → {al.dst}:{al.dst_port}
                </div>
                <div className="text-sm text-gray-600 truncate">
                  {al.payload_preview.slice(0, 20)}
                </div>
                <div className="text-xs text-gray-400">{al.time}</div>
              </div>
              <div>
                <span
                  className={`text-xs text-white px-2 py-1 rounded-full ${severityColor(
                    al.severity
                  )}`}
                >
                  {al.severity.toUpperCase()}
                </span>
              </div>
            </div>
          ))}
        </div>

      </div>

      {/* Main detail view */}
      <div className="flex-1 p-6 overflow-y-auto">
        {!selected ? (
          <div className="text-gray-500">
            <h3 className="text-lg font-semibold">No alert selected</h3>
            <p>Click an alert on the left to inspect details.</p>
          </div>
        ) : (
          <div className="space-y-5">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold">Alert: {selected.id}</h3>
              <div className="text-xs text-gray-500">{selected.time}</div>
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="font-semibold">Src</div>
                <div>{selected.src}:{selected.src_port}</div>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="font-semibold">Dst</div>
                <div>{selected.dst}:{selected.dst_port}</div>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="font-semibold">Proto</div>
                <div>{selected.protocol}</div>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-1">Reason</h4>
              <div className="bg-white shadow p-3 rounded-lg">
                {selected.reason}
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-1">Payload preview</h4>
              {selected.payload_label === "TLS/ENCRYPTED" ? (
                <>
                <span className="p-3 rounded-lg bg-yellow-50 text-sm">Encrypted TLS payload</span>
                <button className = "p-2 rounded-lg bg-blue-300 text-sm hover:bg-blue-400 hover:cursor-pointer"  type="button" onClick={() => setShowPreview(!showPreview)}>Show Anyways</button>
                {showPreview && (
                  <div className="bg-slate-900 text-slate-200 p-3 rounded-lg overflow-x-auto text-sm mt-2">{selected.payload_preview}</div>
                )}
                </>
              ) : selected.payload_label === "EMPTY" ? (
                <div className="p-3 rounded-lg bg-gray-50 text-sm">No payload</div>
              ): (
                <pre className="bg-slate-900 text-slate-200 p-3 rounded-lg overflow-x-auto text-sm">  
                  {selected.payload_ascii}
                </pre>
              )}
            </div>
            <div>
            <div>
              <h4 className="font-semibold mb-1">Raw hex</h4>
              <pre className="bg-black text-green-400 p-3 rounded-lg overflow-x-auto text-xs">
                {selected.raw_hex}
              </pre>
            </div>

            <div className="flex gap-2">
              <button
                className="px-3 py-1 rounded-lg bg-blue-500 text-white hover:bg-blue-600 text-sm"
                onClick={() => {
                  const ws = wsRef.current;
                  if (ws && ws.readyState === WebSocket.OPEN)
                    ws.send(JSON.stringify({ type: "ack", id: selected.id }));
                  alert("Acknowledged");
                }}
              >
                Acknowledge
              </button>
              <button
                className="px-3 py-1 rounded-lg bg-gray-200 hover:bg-gray-300 text-sm"
                onClick={() => {
                  navigator.clipboard.writeText(
                    JSON.stringify(selected, null, 2)
                  );
                  alert("Copied JSON to clipboard");
                }}
              >
                Copy JSON
              </button>
            </div>
          </div>
        </div>
        )}
    </div>
    </div>
  );
}
