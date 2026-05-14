import React from "react";
import ReactDOM from "react-dom/client";
import GhostTraceApp from "./GhostTrace.jsx";

class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, errorMessage: "" };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, errorMessage: error?.message || "Unknown frontend error" };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 24, fontFamily: "Segoe UI, sans-serif" }}>
          <h2>GhostTrace UI Error</h2>
          <p>The frontend hit a runtime error instead of rendering a blank page.</p>
          <pre style={{ whiteSpace: "pre-wrap" }}>{this.state.errorMessage}</pre>
          <p>Open browser DevTools Console for full stack trace.</p>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <GhostTraceApp />
    </AppErrorBoundary>
  </React.StrictMode>
);
