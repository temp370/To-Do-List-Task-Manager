-- Daily Habit Tracker: fixed challenges, secure attendance/XP, and idempotent legacy-task import.
-- Review existing policies and take a backup before applying to production.
-- This migration does not delete application rows. It deliberately preserves unknown policies.

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

-- Do not remove unrelated policies. These owner policies are additive; the companion
-- restrictive policies in the follow-up hardening migration enforce per-user ownership.
do $$
begin
  if to_regclass('public.tasks') is null then
    raise exception 'Expected public.tasks table was not found. Verify the existing tasks table before applying this migration.';
  end if;
  if to_regclass('public.app_settings') is null then
    raise exception 'Expected public.app_settings table was not found. Verify the existing app_settings table before applying this migration.';
  end if;
  alter table public.tasks enable row level security;
  alter table public.app_settings enable row level security;
end $$;

drop policy if exists "Habit tracker users manage own tasks" on public.tasks;
create policy "Habit tracker users manage own tasks" on public.tasks
  for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "Habit tracker users manage own settings" on public.app_settings;
create policy "Habit tracker users manage own settings" on public.app_settings
  for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
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
set search_path = pg_catalog, auth, public
as $$
declare
  result public.habit_challenges;
  caller_id uuid := auth.uid();
begin
  if caller_id is null then raise exception 'Authentication required'; end if;
  if p_goal_days is null or p_goal_days < 1 or p_goal_days > 365 then
    raise exception 'Goal days must be between 1 and 365';
  end if;
  if p_start_date is null then raise exception 'Start date is required'; end if;

  update public.habit_challenges set is_active = false
    where user_id = caller_id and is_active;
  insert into public.habit_challenges (user_id, goal_days, start_date, end_date, xp, attendance, is_active)
    values (caller_id, p_goal_days, p_start_date, p_start_date + (p_goal_days - 1), 0, '{}'::jsonb, true)
    returning * into result;
  return result;
end;
$$;

-- Deprecated: the browser must not submit trusted XP or attendance values.
create or replace function public.save_habit_challenge_progress(p_challenge_id uuid, p_attendance jsonb, p_xp integer)
returns void
language plpgsql
security definer
set search_path = pg_catalog, auth, public
as $$
begin
  raise exception 'Deprecated RPC. Use refresh_habit_challenge_progress instead.';
end;
$$;

-- Idempotent import: task inserts and marker commit atomically.
create or replace function public.import_legacy_habit_tasks(p_source_key text, p_tasks jsonb)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, auth, public
as $$
declare
  marker_id uuid;
  inserted_count integer;
  item jsonb;
  date_text text;
  parsed_date date;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_source_key is null or length(p_source_key) < 1 or length(p_source_key) > 128 then
    raise exception 'Invalid import source key';
  end if;
  if p_tasks is null or jsonb_typeof(p_tasks) <> 'array' or jsonb_array_length(p_tasks) > 5000 then
    raise exception 'Tasks must be an array containing no more than 5000 rows';
  end if;

  -- Validate every row/date before inserting the idempotency marker.
  for item in select value from jsonb_array_elements(p_tasks) as rows(value) loop
    if jsonb_typeof(item) <> 'object' then raise exception 'Each imported task must be an object'; end if;
    if nullif(btrim(item->>'name'), '') is null then raise exception 'Imported task name is required'; end if;
    date_text := item->>'task_date';
    if date_text is null or date_text !~ '^\d{4}-\d{2}-\d{2}$' then raise exception 'Task date must use YYYY-MM-DD'; end if;
    begin
      parsed_date := date_text::date;
    exception when others then
      raise exception 'Invalid calendar date: %', date_text;
    end;
    if to_char(parsed_date, 'YYYY-MM-DD') <> date_text then raise exception 'Invalid calendar date: %', date_text; end if;
  end loop;

  insert into public.habit_data_imports (user_id, source_key)
    values (auth.uid(), p_source_key)
    on conflict (user_id, source_key) do nothing returning id into marker_id;
  if marker_id is null then return 0; end if;

  insert into public.tasks (user_id, task_date, name, status)
  select auth.uid(), (rows.item->>'task_date')::date,
         left(btrim(rows.item->>'name'), 200),
         case when upper(coalesce(rows.item->>'status', '')) in ('YES', 'NO') then upper(rows.item->>'status') else '' end
    from jsonb_array_elements(p_tasks) as rows(item);
  get diagnostics inserted_count = row_count;
  return inserted_count;
end;
$$;

revoke all on function public.start_habit_challenge(integer, date) from public, anon;
grant execute on function public.start_habit_challenge(integer, date) to authenticated;
revoke all on function public.save_habit_challenge_progress(uuid, jsonb, integer) from public, anon, authenticated;
revoke all on function public.import_legacy_habit_tasks(text, jsonb) from public, anon;
grant execute on function public.import_legacy_habit_tasks(text, jsonb) to authenticated;

commit;
