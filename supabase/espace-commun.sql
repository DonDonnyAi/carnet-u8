-- Espace commun du club : liste U8 + présences des entraînements, partagées entre éducateurs.
-- Tout le monde (connecté) lit. Chacun ajoute des joueurs. Un joueur n'est renommé / supprimé
-- que par celui qui l'a ajouté, ou par l'administrateur (karim@fcm-u8.fr). Les présences : tout le monde.
create or replace function public.karim_uid() returns uuid
  language sql stable security definer set search_path = ''
  as $$ select id from auth.users where lower(email) = 'karim@fcm-u8.fr' limit 1 $$;
revoke all on function public.karim_uid() from public, anon;
grant execute on function public.karim_uid() to authenticated;

create table if not exists public.club_data (
  key text primary key check (key ~ '^(pl|att):[A-Za-z0-9_.:-]{1,120}$'),
  value jsonb not null check (pg_column_size(value) < 20000),
  created_by uuid not null default auth.uid(),
  updated_at timestamptz not null default now()
);
alter table public.club_data enable row level security;
alter table public.club_data force row level security;
revoke all on public.club_data from anon, public;
grant select, insert, update, delete on public.club_data to authenticated;

drop policy if exists "club lecture" on public.club_data;
create policy "club lecture" on public.club_data for select to authenticated using (true);

drop policy if exists "club ajout" on public.club_data;
create policy "club ajout" on public.club_data for insert to authenticated
  with check (created_by = (select auth.uid()));

drop policy if exists "club modification" on public.club_data;
create policy "club modification" on public.club_data for update to authenticated
  using (key like 'att:%' or created_by = (select auth.uid()) or (select auth.uid()) = (select public.karim_uid()))
  with check (key like 'att:%' or created_by = (select auth.uid()) or (select auth.uid()) = (select public.karim_uid()));

drop policy if exists "club suppression" on public.club_data;
create policy "club suppression" on public.club_data for delete to authenticated
  using (key like 'att:%' or created_by = (select auth.uid()) or (select auth.uid()) = (select public.karim_uid()));

select count(*) as regles_club from pg_policies where tablename = 'club_data';
