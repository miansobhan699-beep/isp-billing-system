-- NetFlow ISP Reseller Billing V21
-- Secure multi-user workspace + staff roles/invites.
-- Run this once in Supabase SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.isp_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  workspace_id uuid not null,
  role text not null default 'unassigned' check (role in ('owner','admin','manager','billing','support','unassigned')),
  display_name text,
  created_at timestamptz not null default now()
);

create table if not exists public.isp_workspaces (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{"companies":[],"packages":[],"customers":[],"invoices":[],"payments":[],"expenses":[],"staff":[]}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.isp_staff_invites (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  email text,
  role text not null check (role in ('admin','manager','billing','support')),
  token_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

-- First account becomes the owner. Later accounts start as unassigned until an owner/admin invite is claimed.
create or replace function public.handle_new_isp_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  existing_count integer;
begin
  select count(*) into existing_count from public.isp_profiles;
  if existing_count = 0 then
    insert into public.isp_profiles(user_id, workspace_id, role, display_name)
    values(new.id, new.id, 'owner', coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)))
    on conflict (user_id) do nothing;
  else
    insert into public.isp_profiles(user_id, workspace_id, role, display_name)
    values(new.id, new.id, 'unassigned', coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)))
    on conflict (user_id) do nothing;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_isp_new_user on auth.users;
create trigger trg_isp_new_user
after insert on auth.users
for each row execute function public.handle_new_isp_user();

alter table public.isp_profiles enable row level security;
alter table public.isp_workspaces enable row level security;
alter table public.isp_staff_invites enable row level security;

-- RLS helpers. These SECURITY DEFINER functions avoid recursive policies on
-- isp_profiles and make workspace membership checks reliable.
create or replace function public.get_my_isp_workspace_id()
returns uuid
language sql
security definer
stable
set search_path = public
as $$
  select workspace_id from public.isp_profiles where user_id = auth.uid()
$$;

create or replace function public.get_my_isp_role()
returns text
language sql
security definer
stable
set search_path = public
as $$
  select role from public.isp_profiles where user_id = auth.uid()
$$;

revoke all on function public.get_my_isp_workspace_id() from public;
revoke all on function public.get_my_isp_role() from public;
grant execute on function public.get_my_isp_workspace_id() to authenticated;
grant execute on function public.get_my_isp_role() to authenticated;

-- Profiles: users can see their own profile; admins can see members of their workspace.
drop policy if exists profile_select on public.isp_profiles;
create policy profile_select on public.isp_profiles for select using (
  user_id = auth.uid()
  or (
    workspace_id = public.get_my_isp_workspace_id()
    and public.get_my_isp_role() in ('owner','admin')
  )
);

drop policy if exists profile_update_self on public.isp_profiles;
create policy profile_update_self on public.isp_profiles for update
using (user_id = auth.uid())
with check (user_id = auth.uid());

-- Workspace row is owned by the workspace_id (owner user id), but members can access it.
drop policy if exists workspace_select_member on public.isp_workspaces;
create policy workspace_select_member on public.isp_workspaces for select using (
  user_id = public.get_my_isp_workspace_id()
  and public.get_my_isp_role() <> 'unassigned'
);

drop policy if exists workspace_insert_admin on public.isp_workspaces;
create policy workspace_insert_admin on public.isp_workspaces for insert with check (
  user_id = public.get_my_isp_workspace_id()
  and public.get_my_isp_role() in ('owner','admin','manager')
);

drop policy if exists workspace_update_editor on public.isp_workspaces;
create policy workspace_update_editor on public.isp_workspaces for update
using (
  user_id = public.get_my_isp_workspace_id()
  and public.get_my_isp_role() in ('owner','admin','manager','billing')
)
with check (user_id = public.get_my_isp_workspace_id());

drop policy if exists workspace_delete_owner on public.isp_workspaces;
create policy workspace_delete_owner on public.isp_workspaces for delete using (
  user_id = public.get_my_isp_workspace_id()
  and public.get_my_isp_role() = 'owner'
);

-- Backfill profiles for users that already existed before this V15 SQL was run.
do $$
declare
  first_user uuid;
begin
  if not exists (select 1 from public.isp_profiles) then
    select id into first_user from auth.users order by created_at limit 1;
    if first_user is not null then
      insert into public.isp_profiles(user_id,workspace_id,role,display_name)
      values(first_user,first_user,'owner',coalesce((select raw_user_meta_data->>'name' from auth.users where id=first_user),split_part((select email from auth.users where id=first_user),'@',1)))
      on conflict do nothing;
      insert into public.isp_profiles(user_id,workspace_id,role,display_name)
      select id,id,'unassigned',coalesce(raw_user_meta_data->>'name',split_part(email,'@',1))
      from auth.users where id <> first_user
      on conflict do nothing;
    end if;
  end if;
end $$;

-- Invite table is not directly writable by the browser. Use RPCs below.
drop policy if exists invite_select_admin on public.isp_staff_invites;
create policy invite_select_admin on public.isp_staff_invites for select using (
  workspace_id = public.get_my_isp_workspace_id()
  and public.get_my_isp_role() in ('owner','admin')
);

create or replace function public.create_staff_invite(p_email text, p_role text, p_expires_days integer default 7)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  me public.isp_profiles;
  raw_token text;
  hashed text;
begin
  select * into me from public.isp_profiles where user_id = auth.uid();
  if me.role not in ('owner','admin') then raise exception 'Only Owner/Admin can create staff invites'; end if;
  if p_role not in ('admin','manager','billing','support') then raise exception 'Invalid staff role'; end if;
  if p_expires_days < 1 or p_expires_days > 30 then raise exception 'Invite expiry must be 1-30 days'; end if;
  raw_token := encode(gen_random_bytes(24),'hex');
  hashed := encode(digest(raw_token,'sha256'),'hex');
  insert into public.isp_staff_invites(workspace_id,email,role,token_hash,expires_at,created_by)
  values(me.workspace_id,nullif(lower(trim(p_email)),''),p_role,hashed,now() + make_interval(days=>p_expires_days),auth.uid());
  return raw_token;
end;
$$;

create or replace function public.claim_staff_invite(p_token text)
returns public.isp_profiles
language plpgsql
security definer
set search_path = public
as $$
declare
  inv public.isp_staff_invites;
  me public.isp_profiles;
  hashed text;
  out_profile public.isp_profiles;
begin
  select * into me from public.isp_profiles where user_id = auth.uid();
  if me.user_id is null then raise exception 'Profile not found'; end if;
  hashed := encode(digest(p_token,'sha256'),'hex');
  select * into inv from public.isp_staff_invites where token_hash = hashed and used_at is null and expires_at > now() limit 1;
  if inv.id is null then raise exception 'Invite is invalid, expired, or already used'; end if;
  if inv.email is not null and lower(inv.email) <> lower(coalesce((select email from auth.users where id=auth.uid()),'')) then raise exception 'Invite email does not match this account'; end if;
  update public.isp_profiles set workspace_id=inv.workspace_id, role=inv.role where user_id=auth.uid() returning * into out_profile;
  update public.isp_staff_invites set used_at=now() where id=inv.id;
  return out_profile;
end;
$$;

grant execute on function public.create_staff_invite(text,text,integer) to authenticated;
grant execute on function public.claim_staff_invite(text) to authenticated;

-- Keep updated_at current.
create or replace function public.set_isp_workspace_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end; $$;

drop trigger if exists trg_isp_workspace_updated_at on public.isp_workspaces;
create trigger trg_isp_workspace_updated_at before update on public.isp_workspaces for each row execute function public.set_isp_workspace_updated_at();

-- IMPORTANT: do not put the service-role key in the website.


-- V20: enable Supabase Realtime for cross-device dashboard updates.
-- Safe to run after the main setup. If the table is already in the publication, nothing changes.
do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'isp_workspaces'
  ) then
    alter publication supabase_realtime add table public.isp_workspaces;
  end if;
end $$;
