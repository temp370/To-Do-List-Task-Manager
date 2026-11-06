-- Daily Habit Tracker: fixed challenges, cloud attendance/XP, and safe legacy task import.
-- Run once in Supabase Dashboard > SQL Editor. This migration adds tables/functions and
-- replaces task/settings policies with per-user policies; it does not delete table data.

begin;

create table if not exists public.habit_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  goal_days integer not null check (goal_days between 1 and 365),
  start_date date not null,
  end_date date not null,
  xp integer not null default 0 check (xp >= 0),
  attendance jsonb not null default '{}'::jsonb check (jsonb_typeof(attendance) = 'object'),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  constraint habit_challenges_dates_match check (end_date = start_date + (goal_days - 1))
);

create unique index if not exists habit_challenges_one_active_per_user
  on public.habit_challenges (user_id) where is_active;
create index if not exists habit_challenges_user_created
  on public.habit_challenges (user_id, created_at desc);

alter table public.habit_challenges enable row level security;
drop policy if exists "Users can read own habit challenges" on public.habit_challenges;
create policy "Users can read own habit challenges"
  on public.habit_challenges for select to authenticated using (auth.uid() = user_id);
grant select on public.habit_challenges to authenticated;

-- Keep app_settings and tasks usable by the app while ensuring each authenticated user
-- can access only rows whose user_id matches their Supabase account. Existing data stays intact.
do $$
declare policy_row record;
begin
  if to_regclass('public.tasks') is null then
    raise exception 'Expected public.tasks table was not found. Create/verify the existing tasks table before running this migration.';
  end if;
  if to_regclass('public.app_settings') is null then
    raise exception 'Expected public.app_settings table was not found. Create/verify the existing app_settings table before running this migration.';
  end if;

  alter table public.tasks enable row level security;
  for policy_row in select policyname from pg_policies where schemaname = 'public' and tablename = 'tasks' loop
    execute format('drop policy %I on public.tasks', policy_row.policyname);
  end loop;
  create policy "Habit tracker users manage own tasks" on public.tasks
    for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);

  alter table public.app_settings enable row level security;
  for policy_row in select policyname from pg_policies where schemaname = 'public' and tablename = 'app_settings' loop
    execute format('drop policy %I on public.app_settings', policy_row.policyname);
  end loop;
  create policy "Habit tracker users manage own settings" on public.app_settings
    for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
end $$;

grant select, insert, update, delete on public.tasks, public.app_settings to authenticated;

create table if not exists public.habit_data_imports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  source_key text not null,
  imported_at timestamptz not null default now(),
  unique (user_id, source_key)
);
alter table public.habit_data_imports enable row level security;
grant select on public.habit_data_imports to authenticated;
drop policy if exists "Users can read own migration markers" on public.habit_data_imports;
create policy "Users can read own migration markers" on public.habit_data_imports
  for select to authenticated using (auth.uid() = user_id);

create or replace function public.start_habit_challenge(p_goal_days integer, p_start_date date)
returns public.habit_challenges
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  result public.habit_challenges;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_goal_days is null or p_goal_days < 1 or p_goal_days > 365 then
    raise exception 'Goal days must be between 1 and 365';
  end if;
  if p_start_date is null then raise exception 'Start date is required'; end if;

  update public.habit_challenges set is_active = false
    where user_id = auth.uid() and is_active;
  insert into public.habit_challenges (user_id, goal_days, start_date, end_date, xp, attendance, is_active)
    values (auth.uid(), p_goal_days, p_start_date, p_start_date + (p_goal_days - 1), 0, '{}'::jsonb, true)
    returning * into result;
  return result;
end;
$$;

create or replace function public.save_habit_challenge_progress(p_challenge_id uuid, p_attendance jsonb, p_xp integer)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_attendance is null or jsonb_typeof(p_attendance) <> 'object' then raise exception 'Attendance must be a JSON object'; end if;
  if p_xp is null or p_xp < 0 then raise exception 'XP must be zero or more'; end if;
  update public.habit_challenges
    set attendance = p_attendance, xp = greatest(xp, p_xp)
    where id = p_challenge_id and user_id = auth.uid() and is_active;
  if not found then raise exception 'Active challenge not found or access denied'; end if;
end;
$$;

-- Idempotent import: a unique per-user source key and task inserts commit atomically.
create or replace function public.import_legacy_habit_tasks(p_source_key text, p_tasks jsonb)
returns integer
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  marker_id uuid;
  inserted_count integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_source_key is null or length(p_source_key) < 1 or length(p_source_key) > 128 then
    raise exception 'Invalid import source key';
  end if;
  if p_tasks is null or jsonb_typeof(p_tasks) <> 'array' or jsonb_array_length(p_tasks) > 5000 then
    raise exception 'Tasks must be an array containing no more than 5000 rows';
  end if;
  insert into public.habit_data_imports (user_id, source_key)
    values (auth.uid(), p_source_key) on conflict (user_id, source_key) do nothing returning id into marker_id;
  if marker_id is null then return 0; end if;

  insert into public.tasks (user_id, task_date, name, status)
  select auth.uid(), (item->>'task_date')::date,
         left(trim(item->>'name'), 200),
         case when upper(coalesce(item->>'status', '')) in ('YES', 'NO') then upper(item->>'status') else '' end
    from jsonb_array_elements(p_tasks) as item
   where nullif(trim(item->>'name'), '') is not null
     and coalesce(item->>'task_date', '') ~ '^\d{4}-\d{2}-\d{2}$';
  get diagnostics inserted_count = row_count;
  return inserted_count;
end;
$$;

revoke all on function public.start_habit_challenge(integer, date) from public;
revoke all on function public.save_habit_challenge_progress(uuid, jsonb, integer) from public;
revoke all on function public.import_legacy_habit_tasks(text, jsonb) from public;
grant execute on function public.start_habit_challenge(integer, date) to authenticated;
grant execute on function public.save_habit_challenge_progress(uuid, jsonb, integer) to authenticated;
grant execute on function public.import_legacy_habit_tasks(text, jsonb) to authenticated;

commit;
