-- Persist the user's recurring daily task list without changing or deleting task history.
-- Each day's completion remains stored separately in public.tasks by task_date.
begin;

alter table public.app_settings
  add column if not exists task_templates jsonb not null default '[]'::jsonb;

-- Safely seed recurring tasks from existing history for users whose template list is empty.
-- Historical task rows and statuses are preserved unchanged.
update public.app_settings as settings
set task_templates = coalesce((
  select jsonb_agg(jsonb_build_object('name', task_names.name) order by task_names.name)
  from (
    select distinct btrim(tasks.name) as name
    from public.tasks
    where tasks.user_id = settings.user_id
      and nullif(btrim(tasks.name), '') is not null
  ) as task_names
), '[]'::jsonb)
where settings.task_templates = '[]'::jsonb
  and exists (
    select 1 from public.tasks
    where tasks.user_id = settings.user_id
      and nullif(btrim(tasks.name), '') is not null
  );

commit;
