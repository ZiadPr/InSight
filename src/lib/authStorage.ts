const SESSION_TOKEN_KEY = "workpulse_session_token";

export function getStoredSessionToken(): string | null {
  try {
    return window.sessionStorage.getItem(SESSION_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setStoredSessionToken(token: string): void {
  try {
    window.sessionStorage.setItem(SESSION_TOKEN_KEY, token);
  } catch {
    // Ignore storage unavailability
  }
}

export function clearStoredSessionToken(): void {
  try {
    window.sessionStorage.removeItem(SESSION_TOKEN_KEY);
  } catch {
    // Ignore storage unavailability
  }
}

export function authHeaders(): Record<string, string> {
  const token = getStoredSessionToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
