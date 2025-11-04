class Rosboard {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.reconnectInterval = 3000; // retry every 3 seconds
  }

  connect(host = window.location.hostname, port = 8899) {
    const url = `ws://${host}:${port}/v1`;
    console.log(`[Rosboard] Connecting to ${url} ...`);

    try {
      this.socket = new WebSocket(url);
    } catch (err) {
      console.error("[Rosboard] ❌ Failed to create WebSocket:", err);
      this.retryConnect(host, port);
      return;
    }

    this.socket.onopen = () => {
      this.isConnected = true;
      console.log("[Rosboard] ✅ Connected to backend!");
    };

    this.socket.onmessage = (event) => {
      // Handle messages here
      // Example: console.log("[Rosboard] Data:", event.data);
    };

    this.socket.onclose = () => {
      this.isConnected = false;
      console.warn("[Rosboard] ⚠️ Disconnected from backend");
      this.retryConnect(host, port);
    };

    this.socket.onerror = (error) => {
      console.error("[Rosboard] ❌ WebSocket error:", error);
      this.socket.close();
    };
  }

  retryConnect(host, port) {
    console.log(`[Rosboard] 🔄 Retrying connection in ${this.reconnectInterval / 1000}s...`);
    setTimeout(() => this.connect(host, port), this.reconnectInterval);
  }
}

// Example usage:
const rosboard = new Rosboard();
rosboard.connect();
