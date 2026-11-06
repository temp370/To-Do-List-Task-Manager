-- Daily Habit Tracker schema and security baseline.
-- Before production use, review existing RLS policies and take a backup.
-- This migration preserves unrelated policies and application rows.
begin;

create table if not exists public.habit_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  goal_days integer not null check (goal_days between 1 and 365),
  start_date date not null,
  end_date date not null,
  xp bigint not null default 0 check (xp >= 0),
  attendance jsonb not null default '{}'::jsonb check (jsonb_typeof(attendance) = 'object'),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  constraint habit_challenges_dates_match check (end_date = start_date + (goal_days - 1))
);
alter table public.habit_challenges alter column xp type bigint using xp::bigint;
create unique index if not exists habit_challenges_one_active_per_user on public.habit_challenges(user_id) where is_active;
create index if not exists habit_challenges_user_created on public.habit_challenges(user_id, created_at desc);
alter table public.habit_challenges enable row level security;
drop policy if exists "Users can read own habit challenges" on public.habit_challenges;
create policy "Users can read own habit challenges" on public.habit_challenges
  for select to authenticated using (auth.uid() = user_id);
revoke all on public.habit_challenges from public, anon;
grant select on public.habit_challenges to authenticated;

create table if not exists public.habit_data_imports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  source_key text not null,
  imported_at timestamptz not null default now(),
  unique (user_id, source_key)
);
create unique index if not exists habit_data_imports_user_source_key_uidx
  on public.habit_data_imports(user_id, source_key);
alter table public.habit_data_imports enable row level security;
drop policy if exists "Users can read own migration markers" on public.habit_data_imports;
create policy "Users can read own migration markers" on public.habit_data_imports
  for select to authenticated using (auth.uid() = user_id);
revoke all on public.habit_data_imports from public, anon;
grant select on public.habit_data_imports to authenticated;

-- Keep existing policy definitions. Add this app-owned permissive policy, plus a
-- restrictive owner gate so any other permissive policy cannot expose another user's rows.
do $$
begin
  if to_regclass('public.tasks') is null or to_regclass('public.app_settings') is null then
    raise exception 'Expected public.tasks and public.app_settings tables. Verify schema before applying.';
  end if;
  alter table public.tasks enable row level security;
  alter table public.app_settings enable row level security;
end $$;
drop policy if exists "Habit tracker users manage own tasks" on public.tasks;
create policy "Habit tracker users manage own tasks" on public.tasks
  for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "Habit tracker enforce own task rows" on public.tasks;
create policy "Habit tracker enforce own task rows" on public.tasks
  as restrictive for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "Habit tracker users manage own settings" on public.app_settings;
create policy "Habit tracker users manage own settings" on public.app_settings
  for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "Habit tracker enforce own settings rows" on public.app_settings;
create policy "Habit tracker enforce own settings rows" on public.app_settings
  as restrictive for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
revoke all on public.tasks, public.app_settings from public, anon;
grant select, insert, update, delete on public.tasks, public.app_settings to authenticated;

create or replace function public.start_habit_challenge(p_goal_days integer, p_start_date date)
returns public.habit_challenges language plpgsql security definer
set search_path = pg_catalog, auth, public as $$
declare result public.habit_challenges; caller_id uuid := auth.uid();
begin
  if caller_id is null then raise exception 'Authentication required'; end if;
  if p_goal_days is null or p_goal_days < 1 or p_goal_days > 365 then raise exception 'Goal days must be between 1 and 365'; end if;
  if p_start_date is null then raise exception 'Start date is required'; end if;
  update public.habit_challenges set is_active=false where user_id=caller_id and is_active;
  insert into public.habit_challenges(user_id,goal_days,start_date,end_date,xp,attendance,is_active)
    values(caller_id,p_goal_days,p_start_date,p_start_date+(p_goal_days-1),0,'{}'::jsonb,true)
    returning * into result;
  return result;
end; $$;

create or replace function public.end_habit_challenge(p_challenge_id uuid)
returns void language plpgsql security definer
set search_path = pg_catalog, auth, public as $$
declare caller_id uuid := auth.uid();
begin
  if caller_id is null then raise exception 'Authentication required'; end if;
  update public.habit_challenges set is_active=false
   where id=p_challenge_id and user_id=caller_id and is_active;
  if not found then raise exception 'Active challenge not found or access denied'; end if;
end; $$;

-- Recalculate from cloud tasks. The browser supplies its IANA timezone only for
-- the local-calendar cutoff; the client cannot prove that the timezone is truthful.
create or replace function public.refresh_habit_challenge_progress(p_challenge_id uuid,p_timezone text)
returns void language plpgsql security definer
set search_path = pg_catalog, auth, public as $$
declare
  caller_id uuid := auth.uid(); v_start date; v_end date; v_today date;
  v_attendance jsonb; v_xp bigint;
begin
  if caller_id is null then raise exception 'Authentication required'; end if;
  if p_timezone is null or not exists(select 1 from pg_catalog.pg_timezone_names z where z.name=p_timezone) then
    raise exception 'Invalid IANA timezone';
  end if;
  select c.start_date,c.end_date into v_start,v_end from public.habit_challenges c
   where c.id=p_challenge_id and c.user_id=caller_id and c.is_active;
  if not found then raise exception 'Active challenge not found or access denied'; end if;
  v_today := (pg_catalog.now() at time zone p_timezone)::date;
  select coalesce(pg_catalog.jsonb_object_agg(pg_catalog.to_char(d.day,'YYYY-MM-DD'),
    case when d.day>v_today then 'future'
         when d.day=v_today and coalesce(t.total,0)>0 and t.done=t.total then 'present'
         when d.day=v_today then 'pending'
         when coalesce(t.total,0)>0 and t.done=t.total then 'present'
         else 'absent' end), '{}'::jsonb)
    into v_attendance
    from pg_catalog.generate_series(v_start::timestamp,v_end::timestamp,interval '1 day') as d(day)
    left join lateral (
      select count(*)::bigint as total,
             count(*) filter(where x.status='YES')::bigint as done
        from public.tasks x where x.user_id=caller_id and x.task_date=d.day::date
    ) t on true;
  select count(*)::bigint*10 into v_xp from public.tasks x
   where x.user_id=caller_id and x.task_date between v_start and v_end and x.status='YES';
  update public.habit_challenges set attendance=v_attendance,xp=v_xp
   where id=p_challenge_id and user_id=caller_id and is_active;
  if not found then raise exception 'Active challenge not found or access denied'; end if;
end; $$;

-- Never trust client-supplied progress. Retain the old signature only to return a clear error.
create or replace function public.save_habit_challenge_progress(p_challenge_id uuid,p_attendance jsonb,p_xp integer)
returns void language plpgsql security definer
set search_path = pg_catalog, auth, public as $$
begin
  raise exception 'Deprecated RPC. Use refresh_habit_challenge_progress instead.';
end; $$;

create or replace function public.import_legacy_habit_tasks(p_source_key text,p_tasks jsonb)
returns integer language plpgsql security definer
set search_path = pg_catalog, auth, public as $$
declare marker_id uuid; inserted_count integer; item jsonb; date_text text; parsed_date date;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_source_key is null or length(p_source_key)<1 or length(p_source_key)>128 then raise exception 'Invalid import source key'; end if;
  if p_tasks is null or jsonb_typeof(p_tasks)<>'array' or jsonb_array_length(p_tasks)>5000 then raise exception 'Tasks must be an array of at most 5000 rows'; end if;
  for item in select rows.value from jsonb_array_elements(p_tasks) as rows(value) loop
    if jsonb_typeof(item)<>'object' or nullif(btrim(item->>'name'),'') is null then raise exception 'Each imported task needs a name'; end if;
    date_text:=item->>'task_date';
    if date_text is null or date_text !~ '^\d{4}-\d{2}-\d{2}$' then raise exception 'Task date must use YYYY-MM-DD'; end if;
    begin parsed_date:=date_text::date; exception when others then raise exception 'Invalid calendar date: %',date_text; end;
    if pg_catalog.to_char(parsed_date,'YYYY-MM-DD')<>date_text then raise exception 'Invalid calendar date: %',date_text; end if;
  end loop;
  insert into public.habit_data_imports(user_id,source_key) values(auth.uid(),p_source_key)
    on conflict(user_id,source_key) do nothing returning id into marker_id;
  if marker_id is null then return 0; end if;
  insert into public.tasks(user_id,task_date,name,status)
  select auth.uid(),(rows.item->>'task_date')::date,left(btrim(rows.item->>'name'),200),
    case when upper(coalesce(rows.item->>'status','')) in ('YES','NO') then upper(rows.item->>'status') else '' end
  from jsonb_array_elements(p_tasks) as rows(item);
  get diagnostics inserted_count=row_count;
  return inserted_count;
end; $$;

revoke all on function public.start_habit_challenge(integer,date) from public,anon,authenticated;
grant execute on function public.start_habit_challenge(integer,date) to authenticated;
revoke all on function public.end_habit_challenge(uuid) from public,anon,authenticated;
grant execute on function public.end_habit_challenge(uuid) to authenticated;
revoke all on function public.refresh_habit_challenge_progress(uuid,text) from public,anon,authenticated;
grant execute on function public.refresh_habit_challenge_progress(uuid,text) to authenticated;
revoke all on function public.save_habit_challenge_progress(uuid,jsonb,integer) from public,anon,authenticated;
revoke all on function public.import_legacy_habit_tasks(text,jsonb) from public,anon,authenticated;
grant execute on function public.import_legacy_habit_tasks(text,jsonb) to authenticated;

commit;
