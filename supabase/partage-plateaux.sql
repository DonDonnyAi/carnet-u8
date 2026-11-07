-- Plateaux partagés : chaque éducateur peut LIRE les équipes et les matchs des plateaux
-- de karim@fcm-u8.fr (rubrique "mt" uniquement). Personne ne peut les modifier.
create or replace function public.karim_uid() returns uuid
  language sql stable security definer set search_path = ''
  as $$ select id from auth.users where lower(email) = 'karim@fcm-u8.fr' limit 1 $$;
revoke all on function public.karim_uid() from public, anon;
grant execute on function public.karim_uid() to authenticated;

drop policy if exists "plateaux partages" on public.carnet_data;
create policy "plateaux partages" on public.carnet_data
  for select to authenticated
  using (key = 'mt' and owner = (select public.karim_uid()));
