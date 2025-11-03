class Rosboard {
  constructor() {
    this.socket = null;
    this.isConnected = false;
  }

  connect(url) {
    console.log(`[Rosboard] Connecting to ${url} ...`);
    this.socket = new WebSocket(url);

    this.socket.onopen = () => {
      this.isConnected = true;
      console.log("[Rosboard] ✅ Connected to backend!");
    };

    this.socket.onmessage = (event) => {
      // You can handle incoming data here if needed
      // e.g. console.log("Data:", event.data);
    };

    this.socket.onclose = () => {
      this.isConnected = false;
      console.warn("[Rosboard] ⚠️ Disconnected from backend");
    };

    this.socket.onerror = (error) => {
      console.error("[Rosboard] ❌ WebSocket error:", error);
    };
  }
}
