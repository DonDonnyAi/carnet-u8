// Edge Function Supabase : gestion des comptes éducateurs.
// Réservée à l'administrateur (ADMIN_EMAIL). La clé secrète reste côté serveur (variables Supabase).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const ADMIN_EMAIL = "karim@fcm-u8.fr";
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return reply({ error: "Méthode non autorisée." }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  // 1. Qui appelle ? On vérifie le jeton auprès de Supabase.
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return reply({ error: "Non connecté." }, 401);
  const who = await createClient(url, anon).auth.getUser(token);
  const caller = who.data?.user;
  if (who.error || !caller) return reply({ error: "Session invalide." }, 401);
  if ((caller.email || "").toLowerCase() !== ADMIN_EMAIL) return reply({ error: "Accès réservé à l'administrateur." }, 403);

  const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
  let p: Record<string, string> = {};
  try { p = await req.json(); } catch (_) { return reply({ error: "Requête illisible." }, 400); }
  const email = String(p.email || "").trim().toLowerCase();
  const password = String(p.password || "");

  try {
    if (p.action === "list") {
      const r = await admin.auth.admin.listUsers({ page: 1, perPage: 200 });
      if (r.error) throw r.error;
      const users = r.data.users.map((u) => ({
        id: u.id, email: u.email, created_at: u.created_at, last_sign_in_at: u.last_sign_in_at,
        admin: (u.email || "").toLowerCase() === ADMIN_EMAIL,
      }));
      return reply({ users });
    }
    if (p.action === "create") {
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return reply({ error: "Email invalide." }, 400);
      if (password.length < 8) return reply({ error: "Mot de passe : 8 caractères minimum." }, 400);
      const r = await admin.auth.admin.createUser({ email, password, email_confirm: true });
      if (r.error) return reply({ error: /already|exists|registered/i.test(r.error.message) ? "Cet email a déjà un compte." : r.error.message }, 400);
      return reply({ ok: true, id: r.data.user?.id });
    }
    if (p.action === "reset") {
      if (!p.id) return reply({ error: "Compte manquant." }, 400);
      if (password.length < 8) return reply({ error: "Mot de passe : 8 caractères minimum." }, 400);
      const r = await admin.auth.admin.updateUserById(p.id, { password });
      if (r.error) throw r.error;
      return reply({ ok: true });
    }
    if (p.action === "delete") {
      if (!p.id) return reply({ error: "Compte manquant." }, 400);
      if (p.id === caller.id) return reply({ error: "Tu ne peux pas supprimer ton propre compte." }, 400);
      await admin.from("carnet_data").delete().eq("owner", p.id);
      const r = await admin.auth.admin.deleteUser(p.id);
      if (r.error) throw r.error;
      return reply({ ok: true });
    }
    return reply({ error: "Action inconnue." }, 400);
  } catch (e) {
    return reply({ error: String((e as Error).message || e) }, 500);
  }
});
