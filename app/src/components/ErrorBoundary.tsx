import { Component, type ErrorInfo, type ReactNode } from "react";

interface State {
  error: Error | null;
}

/**
 * A render error in one card must not take the window down to a blank page.
 * The panel's whole job is to be readable at a glance, so a crash reports
 * itself in place.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("patchbay panel crashed", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="shell">
        <header className="header">
          <span className="wordmark">patchbay</span>
          <span className="summary">the panel hit a rendering error</span>
        </header>
        <main className="board">
          <div className="banner">
            <span className="glyph">△</span>
            <span>{this.state.error.message}</span>
          </div>
          <p className="placeholder">reload the window to try again</p>
        </main>
      </div>
    );
  }
}
