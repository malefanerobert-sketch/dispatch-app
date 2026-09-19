// Supabase Edge Function: admin-delete-user
// Fully removes a user's Supabase Auth login (auth.users row) after the admin
// dashboard has deleted their profile data from job_seekers.
//
// Security model:
//   1. The caller must send a valid user access token (Bearer) in the
//      Authorization header. We resolve that token to a real auth user.
//   2. That caller's auth user id must exist in the `dispatch_admins` table.
//   3. Only then do we use the service role key to delete the target auth user.
//
// The service role key is NEVER exposed to the browser — it lives only in the
// SUPABASE_SERVICE_ROLE_KEY env secret configured on this Edge Function.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  try {
    // --- 1. Extract caller token ---
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return json({ error: "Missing Authorization bearer token" }, 401);
    }

    // --- 2. Parse body ---
    let body: { userId?: string };
    try {
      body = await req.json();
    } catch {
      return json({ error: "Invalid JSON body" }, 400);
    }
    const userId = (body.userId || "").trim();
    if (!userId) {
      return json({ error: "Missing userId" }, 400);
    }

    // --- 3. Resolve the caller from their token (anon client) ---
    const callerClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: `Bearer ${token}` } },
    });

    const { data: userData, error: userErr } = await callerClient.auth.getUser(
      token,
    );
    if (userErr || !userData?.user) {
      return json({ error: "Not authenticated" }, 401);
    }
    const callerId = userData.user.id;

    // --- 4. Verify caller is an admin ---
    // Use the service-role client so RLS never hides the admin row from us.
    const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // The dispatch_admins table stores the admin's auth user id. Depending on
    // the schema this may be the `id` column or a `user_id` column, so we try
    // `id` first and fall back to `user_id` if that column doesn't exist.
    let isAdmin = false;
    {
      const { data: byId, error: byIdErr } = await adminClient
        .from("dispatch_admins")
        .select("*")
        .eq("id", callerId)
        .maybeSingle();

      if (!byIdErr && byId) {
        isAdmin = true;
      } else {
        const { data: byUserId, error: byUserIdErr } = await adminClient
          .from("dispatch_admins")
          .select("*")
          .eq("user_id", callerId)
          .maybeSingle();

        if (byUserId) {
          isAdmin = true;
        } else if (byIdErr && byUserIdErr) {
          return json(
            { error: "Admin check failed: " + byIdErr.message },
            500,
          );
        }
      }
    }

    if (!isAdmin) {
      return json({ error: "Forbidden: caller is not an admin" }, 403);
    }

    // --- 5. Delete the target auth user ---
    const { error: delErr } = await adminClient.auth.admin.deleteUser(userId);
    if (delErr) {
      return json({ error: "Delete failed: " + delErr.message }, 500);
    }

    return json({ success: true });
  } catch (e) {
    return json({ error: "Unexpected error: " + (e?.message || String(e)) }, 500);
  }
});
