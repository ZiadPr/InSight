import { createClient, type SupabaseClient, type User } from "https://esm.sh/@supabase/supabase-js@2.49.1";

export function createServiceClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) {
    throw new Error("Missing server Supabase credentials");
  }
  return createClient(url, serviceKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

export async function authenticateRequestUser(
  req: Request,
): Promise<{ user: User | null; jwt: string | null; error: string | null }> {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return { user: null, jwt: null, error: "UNAUTHORIZED" };
  }
  const jwt = authHeader.slice(7).trim();
  if (!jwt) {
    return { user: null, jwt: null, error: "UNAUTHORIZED" };
  }

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!url || !anonKey) {
    return { user: null, jwt: null, error: "SERVER_MISCONFIGURED" };
  }

  const authClient = createClient(url, anonKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  const { data, error } = await authClient.auth.getUser(jwt);
  if (error || !data?.user) {
    return { user: null, jwt: null, error: "UNAUTHORIZED" };
  }

  return { user: data.user, jwt, error: null };
}
