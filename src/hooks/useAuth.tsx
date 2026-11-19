import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  clearStoredSessionToken,
  getStoredSessionToken,
  setStoredSessionToken,
} from "../lib/authStorage";
import {
  resetSecureTransport,
  secureFetchJson,
  SecureTransportError,
} from "../lib/secureTransport";
import type { Profile } from "../types/attendance";

export type AuthErrorCode =
  | "NOT_CONFIGURED"
  | "INVALID_CREDENTIALS"
  | "EMAIL_NOT_CONFIRMED"
  | "PROFILE_NOT_FOUND"
  | "ACCOUNT_UNAVAILABLE"
  | "RATE_LIMITED"
  | "CAPTCHA_REQUIRED"
  | "CAPTCHA_FAILED"
  | "NETWORK_ERROR";

export interface AuthUser {
  id: string;
  email?: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  profile: Profile | null;
  loading: boolean;
  authError: AuthErrorCode | null;
  signIn: (
    email: string,
    password: string,
    turnstileToken?: string,
  ) => Promise<{ ok: boolean; error?: AuthErrorCode; role?: Profile["role"] }>;
  signOut: () => Promise<void>;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  profile: null,
  loading: true,
  authError: null,
  signIn: async () => ({ ok: false }),
  signOut: async () => undefined,
  refreshProfile: async () => undefined,
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<AuthErrorCode | null>(null);

  const loadLocalProfile = useCallback(async (): Promise<Profile | null> => {
    const token = getStoredSessionToken();
    if (!token) {
      setUser(null);
      setProfile(null);
      setAuthError(null);
      return null;
    }

    try {
      const res = await secureFetchJson<{ ok: boolean; profile?: Profile }>("/api/auth/me", {
        method: "GET",
      });
      if (!res.ok || !res.data?.ok || !res.data.profile) {
        clearStoredSessionToken();
        setUser(null);
        setProfile(null);
        return null;
      }
      setUser({ id: res.data.profile.id, email: res.data.profile.email });
      setProfile(res.data.profile);
      setAuthError(null);
      return res.data.profile;
    } catch {
      return null;
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    void loadLocalProfile().finally(() => {
      if (mounted) setLoading(false);
    });
    return () => {
      mounted = false;
    };
  }, [loadLocalProfile]);

  const signIn = useCallback(
    async (
      email: string,
      password: string,
      turnstileToken?: string,
    ): Promise<{ ok: boolean; error?: AuthErrorCode; role?: Profile["role"] }> => {
      setAuthError(null);

      // Express API sign-in (encrypted via ECDH P-256 + AES-256-GCM)
      try {
        const bodyPayload: { email: string; password: string; turnstile_token?: string } = {
          email: email.trim(),
          password,
        };
        if (turnstileToken && turnstileToken.trim().length > 0) {
          bodyPayload.turnstile_token = turnstileToken.trim();
        }
        const res = await secureFetchJson<{
          ok?: boolean;
          token?: string;
          profile?: Profile;
          error?: string;
        }>("/api/auth/login", {
          method: "POST",
          body: bodyPayload,
        });

        const data = res.data;
        if (!res.ok || !data?.ok || !data.token || !data.profile) {
          if (res.status === 429 || data?.error === "RATE_LIMITED") {
            return { ok: false, error: "RATE_LIMITED" };
          }
          if (data?.error === "CAPTCHA_REQUIRED") {
            return { ok: false, error: "CAPTCHA_REQUIRED" };
          }
          if (data?.error === "CAPTCHA_FAILED") {
            return { ok: false, error: "CAPTCHA_FAILED" };
          }
          if (res.status === 403 || data?.error === "ACCOUNT_UNAVAILABLE") {
            return { ok: false, error: "ACCOUNT_UNAVAILABLE" };
          }
          return { ok: false, error: "INVALID_CREDENTIALS" };
        }

        setStoredSessionToken(data.token);
        setUser({ id: data.profile.id, email: data.profile.email });
        setProfile(data.profile);
        return { ok: true, role: data.profile.role };
      } catch (err) {
        if (err instanceof SecureTransportError) {
          if (err.status === 429 || err.code === "RATE_LIMITED") {
            return { ok: false, error: "RATE_LIMITED" };
          }
          if (err.code === "CAPTCHA_REQUIRED") {
            return { ok: false, error: "CAPTCHA_REQUIRED" };
          }
          if (err.code === "CAPTCHA_FAILED") {
            return { ok: false, error: "CAPTCHA_FAILED" };
          }
          if (err.status === 403 && err.code !== "CORS_ORIGIN_REJECTED") {
            return { ok: false, error: "ACCOUNT_UNAVAILABLE" };
          }
        }
        return { ok: false, error: "NETWORK_ERROR" };
      }
    },
    [],
  );

  const signOut = useCallback(async () => {
    await secureFetchJson("/api/auth/logout", {
      method: "POST",
    }).catch(() => undefined);
    clearStoredSessionToken();
    resetSecureTransport();
    setUser(null);
    setProfile(null);
    setAuthError(null);
  }, []);

  const refreshProfile = useCallback(async () => {
    await loadLocalProfile();
  }, [loadLocalProfile]);

  return (
    <AuthContext.Provider
      value={{
        user,
        profile,
        loading,
        authError,
        signIn,
        signOut,
        refreshProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}
