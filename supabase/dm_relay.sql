-- itter DM relay schema (protocol v2, with linked devices).
--
-- Run once against the itter Supabase project (SQL editor, or psql). It only
-- adds dm_* tables and functions; of itter's own tables it reads users and
-- user_public_keys, and reads and writes ignored_users (the ignore list is
-- shared with itter on purpose). Safe to run again.
--
-- Only the relay's service-role key uses these tables: RLS is enabled with no
-- policies, so the anon and authenticated roles can neither read nor write.

-- An earlier version of this file made dm_* tables for one device per account.
-- If they are still there and empty, they are replaced; if they hold data,
-- nothing is touched and this script stops.
do $$
begin
  if to_regclass('public.dm_prekeys') is not null and not exists (
       select 1 from information_schema.columns
       where table_schema = 'public' and table_name = 'dm_prekeys' and column_name = 'device_id') then
    if exists (select 1 from public.dm_identities) then
      raise exception 'The dm_* tables use the old one-device layout and contain data. Clients must set up again after this change; when that is acceptable run: drop table public.dm_inbox, public.dm_otpks, public.dm_prekeys, public.dm_identities cascade;  and then this script again.';
    end if;
    drop table if exists public.dm_inbox, public.dm_otpks, public.dm_prekeys, public.dm_identities cascade;
  end if;
end $$;

-- One DM identity per itter account: the key contacts verify.
create table if not exists public.dm_identities (
  user_id       uuid primary key references public.users(id) on delete cascade,
  username      text not null,
  identity      text not null,        -- base64 of the pqc.IdentityKey encoding
  identity_id   text not null,        -- short public id (pqc.IdentityID)
  recovery_key  text not null,        -- base64: the public key the owner's recovery code stands for
  device_list   text,                 -- the signed pqc.DeviceList (JSON); null until a device is linked
  device_list_v bigint not null default 0,
  created_at    timestamptz not null default now()
);

-- The account's devices: the first one (its key is the identity) and the
-- linked ones named in the signed device list. Everything below hangs off
-- a device and goes when the device goes.
create table if not exists public.dm_devices (
  user_id    uuid not null references public.dm_identities(user_id) on delete cascade,
  device_id  text not null,           -- pqc.IdentityID of the device key
  device_key text not null,           -- base64 of the pqc.IdentityKey encoding
  is_primary boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (user_id, device_id)
);

create table if not exists public.dm_prekeys (
  user_id    uuid not null,
  device_id  text not null,
  spk_id     bigint not null,
  spk        jsonb not null,          -- pqc.PreKeyPublic
  sig        text not null,           -- base64 composite signature by the device key
  created_at timestamptz not null default now(),
  primary key (user_id, device_id),
  foreign key (user_id, device_id) references public.dm_devices(user_id, device_id) on delete cascade
);

create table if not exists public.dm_otpks (
  user_id    uuid not null,
  device_id  text not null,
  otpk_id    bigint not null,
  otpk       jsonb not null,          -- pqc.PreKeyPublic
  created_at timestamptz not null default now(),
  primary key (user_id, device_id, otpk_id),
  foreign key (user_id, device_id) references public.dm_devices(user_id, device_id) on delete cascade
);

create table if not exists public.dm_inbox (
  id            bigserial primary key,
  to_user_id    uuid not null,
  to_device     text not null,
  from_username text not null,
  payload       jsonb not null,       -- opaque pqc.WireMsg (ciphertext)
  created_at    timestamptz not null default now(),
  foreign key (to_user_id, to_device) references public.dm_devices(user_id, device_id) on delete cascade
);
create index if not exists dm_inbox_to_from on public.dm_inbox (to_user_id, to_device, from_username, id);

-- A new device waiting to be linked (kept for 15 minutes).
create table if not exists public.dm_links (
  user_id    uuid not null references public.dm_identities(user_id) on delete cascade,
  link_id    text not null,
  device_key text not null,
  tag        text not null,
  result     text,
  created_at timestamptz not null default now(),
  primary key (user_id, link_id)
);

alter table public.dm_identities enable row level security;
alter table public.dm_devices    enable row level security;
alter table public.dm_prekeys    enable row level security;
alter table public.dm_otpks      enable row level security;
alter table public.dm_inbox      enable row level security;
alter table public.dm_links      enable row level security;

-- Belt and braces: besides RLS, the public API roles get no privileges at all.
revoke all on public.dm_identities, public.dm_devices, public.dm_prekeys, public.dm_otpks, public.dm_inbox, public.dm_links from anon, authenticated;
revoke all on sequence public.dm_inbox_id_seq from anon, authenticated;
grant all on public.dm_identities, public.dm_devices, public.dm_prekeys, public.dm_otpks, public.dm_inbox, public.dm_links to service_role;
grant usage, select on sequence public.dm_inbox_id_seq to service_role;

-- Functions from the one-device layout (their signatures changed).
drop function if exists public.dm_claim_otpk(uuid);
drop function if exists public.dm_senders(uuid);

-- An earlier version stored a hash of the recovery code (recovery_hash) and
-- had the code itself sent in to be compared. Now the relay stores a public
-- key and takes a signature. The column is renamed; identities registered
-- before the change keep working, but their recovery codes no longer do
-- (`itter burn` and a new setup give such an account a code that works).
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'dm_identities' and column_name = 'recovery_hash') then
    alter table public.dm_identities rename column recovery_hash to recovery_key;
  end if;
end $$;
drop function if exists public.dm_register(uuid, text, text, text, text);

-- Bind an identity to an account together with its first device. First
-- writer wins: returns false if the account already has an identity.
create or replace function public.dm_register(p_user_id uuid, p_username text, p_identity text, p_identity_id text, p_recovery_key text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.dm_identities (user_id, username, identity, identity_id, recovery_key)
  values (p_user_id, p_username, p_identity, p_identity_id, p_recovery_key)
  on conflict (user_id) do nothing;
  if not found then
    return false;
  end if;
  insert into public.dm_devices (user_id, device_id, device_key, is_primary)
  values (p_user_id, p_identity_id, p_identity, true);
  return true;
end;
$$;

-- Remove a user's DM identity with everything that depends on it: devices,
-- prekeys, waiting messages and link requests all cascade.
create or replace function public.dm_release_identity(p_user_id uuid)
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.dm_identities where user_id = p_user_id;
$$;

-- The account identity's id and the ids of all its devices (one row each).
create or replace function public.dm_device_ids(p_user_id uuid)
returns table (identity_id text, device_id text)
language sql
stable
security definer
set search_path = public
as $$
  select i.identity_id, d.device_id
  from public.dm_identities i join public.dm_devices d on d.user_id = i.user_id
  where i.user_id = p_user_id;
$$;

-- Store a newer signed device list and make the linked devices match it.
-- p_devices is [{"id": ..., "key": ...}]. Devices that are no longer listed
-- go, with their prekeys and waiting messages. Returns false if p_v is not
-- newer than what is stored.
create or replace function public.dm_set_devices(p_user_id uuid, p_v bigint, p_list text, p_devices jsonb)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.dm_identities set device_list = p_list, device_list_v = p_v
  where user_id = p_user_id and device_list_v < p_v;
  if not found then
    return false;
  end if;
  delete from public.dm_devices d
  where d.user_id = p_user_id and not d.is_primary
    and d.device_id not in (select x->>'id' from jsonb_array_elements(p_devices) x);
  insert into public.dm_devices (user_id, device_id, device_key)
  select p_user_id, x->>'id', x->>'key' from jsonb_array_elements(p_devices) x
  on conflict (user_id, device_id) do nothing;
  return true;
end;
$$;

-- Take a device out of service: its prekeys and waiting messages go.
create or replace function public.dm_clear_device(p_user_id uuid, p_device_id text)
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.dm_otpks   where user_id = p_user_id and device_id = p_device_id;
  delete from public.dm_prekeys where user_id = p_user_id and device_id = p_device_id;
  delete from public.dm_inbox   where to_user_id = p_user_id and to_device = p_device_id;
$$;

-- Hand out one one-time prekey of a device, atomically (never the same one twice).
create or replace function public.dm_claim_otpk(p_user_id uuid, p_device_id text)
returns table (otpk_id bigint, otpk jsonb)
language sql
security definer
set search_path = public
as $$
  delete from public.dm_otpks t
  where (t.user_id, t.device_id, t.otpk_id) = (
    select s.user_id, s.device_id, s.otpk_id from public.dm_otpks s
    where s.user_id = p_user_id and s.device_id = p_device_id
    order by s.otpk_id
    limit 1
    for update skip locked
  )
  returning t.otpk_id, t.otpk;
$$;

-- Queue one message per device of the recipient. p_msgs is
-- {"<device id>": <message>}. A device for which p_limit messages from that
-- sender already wait is left out (a device that is away must not keep the
-- others from getting their copy). Returns false, having stored nothing, if
-- no device had room.
create or replace function public.dm_put_messages(p_to uuid, p_from text, p_msgs jsonb, p_limit integer)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  n integer;
begin
  insert into public.dm_inbox (to_user_id, to_device, from_username, payload)
  select p_to, m.key, p_from, m.value
  from jsonb_each(p_msgs) m
  where (select count(*) from public.dm_inbox i
         where i.to_user_id = p_to and i.to_device = m.key and i.from_username = p_from) < p_limit
  order by m.key;
  get diagnostics n = row_count;
  return n > 0;
end;
$$;

-- Who has messages waiting for a device, and how many.
create or replace function public.dm_senders(p_user_id uuid, p_device_id text)
returns table (from_username text, n integer)
language sql
stable
security definer
set search_path = public
as $$
  select i.from_username, count(*)::integer
  from public.dm_inbox i
  where i.to_user_id = p_user_id and i.to_device = p_device_id
  group by i.from_username;
$$;

-- File a link request (or the same one again) unless p_max are already
-- waiting. Requests older than 15 minutes are dropped on the way.
create or replace function public.dm_put_link(p_user_id uuid, p_link_id text, p_device_key text, p_tag text, p_max integer)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.dm_links where created_at < now() - interval '15 minutes';
  if not exists (select 1 from public.dm_links where user_id = p_user_id and link_id = p_link_id)
     and (select count(*) from public.dm_links where user_id = p_user_id) >= p_max then
    return false;
  end if;
  insert into public.dm_links (user_id, link_id, device_key, tag)
  values (p_user_id, p_link_id, p_device_key, p_tag)
  on conflict (user_id, link_id) do update set device_key = excluded.device_key, tag = excluded.tag, result = null, created_at = now();
  return true;
end;
$$;

-- Ignore someone, the way itter itself does it (ignored_users), and drop
-- what they have waiting.
create or replace function public.dm_ignore(p_user_id uuid, p_other_id uuid, p_other_name text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not exists (select 1 from public.ignored_users where ignorer_id = p_user_id and ignored_user_id = p_other_id) then
    insert into public.ignored_users (ignorer_id, ignored_user_id) values (p_user_id, p_other_id);
  end if;
  delete from public.dm_inbox where to_user_id = p_user_id and from_username = p_other_name;
end;
$$;

do $$
declare f text;
begin
  foreach f in array array[
    'dm_register(uuid, text, text, text, text)', 'dm_release_identity(uuid)', 'dm_device_ids(uuid)',
    'dm_set_devices(uuid, bigint, text, jsonb)', 'dm_clear_device(uuid, text)', 'dm_claim_otpk(uuid, text)',
    'dm_put_messages(uuid, text, jsonb, integer)', 'dm_senders(uuid, text)',
    'dm_put_link(uuid, text, text, text, integer)', 'dm_ignore(uuid, uuid, text)']
  loop
    execute format('revoke all on function public.%s from public, anon, authenticated', f);
    execute format('grant execute on function public.%s to service_role', f);
  end loop;
end $$;

-- Optional housekeeping (e.g. with pg_cron): drop messages nobody fetched.
--   delete from public.dm_inbox where created_at < now() - interval '90 days';

-- Make PostgREST see the new tables and functions right away.
notify pgrst, 'reload schema';
