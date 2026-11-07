-- Preserve daily task insertion order. No task rows or completion history are deleted.
-- This relies on app_settings.task_templates from the persistent-daily-tasks migration.
begin;

-- Keep each user's recurring-task template in its existing order when timestamps tie,
-- and otherwise order templates by the first time that task was added.
update public.app_settings as settings
set task_templates = coalesce((
  select jsonb_agg(to_jsonb(template_name) order by first_seen.created_at nulls last, template_rows.ordinality)
  from jsonb_array_elements(settings.task_templates) with ordinality as template_rows(value, ordinality)
  cross join lateral (
    select coalesce(template_rows.value #>> '{}', template_rows.value ->> 'name') as name
  ) as parsed
  left join lateral (
    select min(task.created_at) as created_at
    from public.tasks as task
    where task.user_id = settings.user_id
      and btrim(task.name) = btrim(parsed.name)
  ) as first_seen on true
  where nullif(btrim(parsed.name), '') is not null
), '[]'::jsonb)
where jsonb_typeof(settings.task_templates) = 'array'
  and jsonb_array_length(settings.task_templates) > 0;

-- Existing task rows are kept; normalize their ordering timestamp so the app's
-- existing ORDER BY created_at renders each day's tasks in the saved template order.
with template_order as (
  select settings.user_id,
         btrim(coalesce(template.value #>> '{}', template.value ->> 'name')) as task_name,
         template.ordinality as task_position
  from public.app_settings as settings
  cross join lateral jsonb_array_elements(settings.task_templates)
    with ordinality as template(value, ordinality)
), ranked_tasks as (
  select task.id,
         min(task.created_at) over (partition by task.user_id, task.task_date) as first_created_at,
         row_number() over (
           partition by task.user_id, task.task_date
           order by coalesce(template_order.task_position, 2147483647), task.created_at, task.id
         ) as position
  from public.tasks as task
  left join template_order
    on template_order.user_id = task.user_id
   and template_order.task_name = btrim(task.name)
)
update public.tasks as task
set created_at = ranked_tasks.first_created_at
                 + ((ranked_tasks.position - 1)::text || ' microseconds')::interval
from ranked_tasks
where task.id = ranked_tasks.id;

-- PostgreSQL's now() is identical for rows inserted in one transaction. This trigger
-- advances created_at by a microsecond as needed, preserving the order rows are inserted.
create or replace function public.preserve_daily_task_insertion_order()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
declare
  latest_created_at timestamptz;
begin
  if new.created_at is null then
    new.created_at := pg_catalog.clock_timestamp();
  end if;

  select max(existing.created_at)
    into latest_created_at
    from public.tasks as existing
   where existing.user_id = new.user_id
     and existing.task_date = new.task_date;

  if latest_created_at is not null and new.created_at <= latest_created_at then
    new.created_at := latest_created_at + interval '1 microsecond';
  end if;

  return new;
end;
$$;

drop trigger if exists preserve_daily_task_insertion_order on public.tasks;
create trigger preserve_daily_task_insertion_order
before insert on public.tasks
for each row execute function public.preserve_daily_task_insertion_order();

commit;
