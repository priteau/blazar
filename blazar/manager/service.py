# Copyright (c) 2013 Mirantis Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
import redis
from stevedore import enabled

from blazar.db import api as db_api
from blazar.db import exceptions as db_ex
from blazar import exceptions as common_ex
from blazar import states
from blazar.i18n import _
from blazar import manager
from blazar.manager import exceptions
from blazar.notification import api as notification_api
from blazar.utils import service as service_utils
from blazar.utils import trusts
from blazar.utils.openstack import keystone

manager_opts = [
    cfg.ListOpt('plugins',
                default=['dummy.vm.plugin'],
                help='All plugins to use (one for every resource type to '
                     'support.)'),
    cfg.IntOpt('minutes_before_end_lease',
               default=60,
               help='Minutes prior to the end of a lease in which actions '
                    'like notification and snapshot are taken. If this is '
                    'set to 0, then these actions are not taken.'),
    cfg.IntOpt('default_max_lease_duration',
               default=-1,
               help='Maximum lease duration in seconds. If this is set to -1, there is not limit. '
                    'For active leases, the limit applies between now and the new end date.'),
    cfg.IntOpt('prolong_seconds_before_lease_end',
               default=48 * 3600,
               help='Number of seconds prior to lease end in which a user can '
                    'request to prolong their lease beyond the maximum lease '
                    'duration. If this is set to 0, then prolonging a lease beyond '
                    'the maximum lease duration is not allowed.'),
    cfg.ListOpt('project_max_lease_durations',
                default=[],
                help='Maximum lease durations overriding the default for specific projects. '
                     'Syntax is a comma-separated list of <project_name>:<seconds> pairs.'),
    cfg.BoolOpt('usage_enforcement', default=False,
                help='Enforce usage limits stored in a database.'),
    cfg.StrOpt('usage_db_host', default='127.0.0.1',
               help='Hostname of the server hosting the usage DB. '
               'It must be a hostname, FQDN, or IP address.'),
    cfg.FloatOpt('usage_default_allocated', default=20000.0,
                 help='Default usage allocated if project missing from usage DB.')
]

CONF = cfg.CONF
CONF.register_opts(manager_opts, 'manager')
LOG = logging.getLogger(__name__)

LEASE_DATE_FORMAT = "%Y-%m-%d %H:%M"


class ManagerService(service_utils.RPCServer):
    """Service class for the blazar-manager service.

    Responsible for working with Blazar DB, scheduling logic, running events,
    working with plugins, etc.
    """

    def __init__(self):
        target = manager.get_target()
        super(ManagerService, self).__init__(target)
        self.plugins = self._get_plugins()
        self.resource_actions = self._setup_actions()
        self.project_max_lease_durations = self._get_project_max_lease_durations()

    def start(self):
        super(ManagerService, self).start()
        self.tg.add_timer(10, self._event)

    def _get_plugins(self):
        """Return dict of resource-plugin class pairs."""
        config_plugins = CONF.manager.plugins
        plugins = {}

        extension_manager = enabled.EnabledExtensionManager(
            check_func=lambda ext: ext.name in config_plugins,
            namespace='blazar.resource.plugins',
            invoke_on_load=False
        )

        invalid_plugins = (set(config_plugins) -
                           set([ext.name for ext
                                in extension_manager.extensions]))
        if invalid_plugins:
            raise common_ex.BlazarException('Invalid plugin names are '
                                            'specified: %s' % invalid_plugins)

        for ext in extension_manager.extensions:
            try:
                plugin_obj = ext.plugin()
            except Exception as e:
                LOG.warning("Could not load {0} plugin "
                            "for resource type {1} '{2}'".format(
                                ext.name, ext.plugin.resource_type, e))
            else:
                if plugin_obj.resource_type in plugins:
                    msg = ("You have provided several plugins for "
                           "one resource type in configuration file. "
                           "Please set one plugin per resource type.")
                    raise exceptions.PluginConfigurationError(error=msg)

                plugins[plugin_obj.resource_type] = plugin_obj
        return plugins

    def _setup_actions(self):
        """Setup actions for each resource type supported.

        BasePlugin interface provides only on_start and on_end behaviour now.
        If there are some configs needed by plugin, they should be returned
        from get_plugin_opts method. These flags are registered in
        [resource_type] group of configuration file.
        """
        actions = {}

        for resource_type, plugin in self.plugins.items():
            plugin = self.plugins[resource_type]
            CONF.register_opts(plugin.get_plugin_opts(), group=resource_type)

            actions[resource_type] = {}
            actions[resource_type]['on_start'] = plugin.on_start
            actions[resource_type]['on_end'] = plugin.on_end
            actions[resource_type]['before_end'] = plugin.before_end
            plugin.setup(None)
        return actions

    @service_utils.with_empty_context
    def _event(self):
        """Tries to commit event.

        If there is an event in Blazar DB to be done, do it and change its
        status to 'DONE'.
        """
        LOG.debug('Trying to get event from DB.')
        event = db_api.event_get_first_sorted_by_filters(
            sort_key='time',
            sort_dir='asc',
            filters={'status': 'UNDONE'}
        )

        if not event:
            return

        if event['time'] < datetime.datetime.utcnow():
            db_api.event_update(event['id'], {'status': 'IN_PROGRESS'})
            event_type = event['event_type']
            event_fn = getattr(self, event_type, None)
            if event_fn is None:
                raise exceptions.EventError(error='Event type %s is not '
                                                  'supported' % event_type)
            try:
                eventlet.spawn_n(service_utils.with_empty_context(event_fn),
                                 event['lease_id'], event['id'])
                lease = db_api.lease_get(event['lease_id'])
                with trusts.create_ctx_from_trust(lease['trust_id']) as ctx:
                    self._send_notification(lease,
                                            ctx,
                                            events=['event.%s' % event_type])
            except Exception:
                db_api.event_update(event['id'], {'status': 'ERROR'})
                LOG.exception(_('Error occurred while event handling.'))

    def _date_from_string(self, date_string, date_format=LEASE_DATE_FORMAT):
        try:
            date = datetime.datetime.strptime(date_string, date_format)
        except ValueError:
            raise exceptions.InvalidDate(date=date_string,
                                         date_format=date_format)

        return date

    def _get_project_max_lease_durations(self):
        max_durations = {}
        max_durations_config = CONF.manager.project_max_lease_durations

        for kv in max_durations_config:
            try:
                project_name, seconds = kv.split(':')
                max_durations[project_name] = int(seconds)
            except ValueError:
                msg = "%s is not a valid project:max_duration pair" % kv
                raise exceptions.ConfigurationError(error=msg)
        return max_durations

    def _check_lease_duration_limit(self, lease_values, project_name, started=False, current_end_date=None):
        start_date = lease_values['start_date']
        end_date = lease_values['end_date']

        now = datetime.datetime.utcnow()
        now = datetime.datetime(now.year, now.month, now.day, now.hour,
                                now.minute)

        lease_duration = end_date - start_date
        if started:
            # Note: an updated end date doesn't necessarily mean that the lease has been prolonged:
            # 1) the end date can be brought closer to now (lease time is reduced)
            # 2) the end date can be moved at the same time as the start date (lease is advanced/deferred)
            # If a lease has already started, the start date cannot be moved, so 2) is not a problem.
            prolong_allowed_from = current_end_date - datetime.timedelta(0, CONF.manager.prolong_seconds_before_lease_end, 0)
            if (now >= prolong_allowed_from):
                lease_duration = end_date - now

        lease_duration_seconds = lease_duration.days * 86400 + lease_duration.seconds
        if project_name in self.project_max_lease_durations:
            project_max_lease_duration = self.project_max_lease_durations[project_name]
            if project_max_lease_duration != -1:
                if (lease_duration_seconds) > project_max_lease_duration:
                    raise common_ex.NotAuthorized(
                        'Lease is longer than maximum allowed of %d seconds for project %s' %
                        (project_max_lease_duration, project_name))
        elif CONF.manager.default_max_lease_duration != -1:

            if (lease_duration_seconds) > CONF.manager.default_max_lease_duration:
                raise common_ex.NotAuthorized(
                    'Lease is longer than maximum allowed of %d seconds' % CONF.manager.default_max_lease_duration)

    def get_lease(self, lease_id):
        return db_api.lease_get(lease_id)

    def list_leases(self, project_id=None):
        return db_api.lease_list(project_id)

    def _get_user_name(self, user_id):
        """Get user name from Keystone"""
        client = keystone.BlazarKeystoneClient(username=CONF.os_admin_username,
                                               password=CONF.os_admin_password,
                                               tenant_name=CONF.os_admin_project_name)
        user = client.users.get(user_id)
        return user.name

    def _get_project_name(self, project_id):
        """Get project name from Keystone"""
        client = keystone.BlazarKeystoneClient(username=CONF.os_admin_username,
                                               password=CONF.os_admin_password,
                                               tenant_name=CONF.os_admin_project_name)
        project = client.projects.get(project_id)
        return project.name

    def create_lease(self, lease_values):
        """Create a lease with reservations.

        Return either the model of created lease or None if any error.
        """
        try:
            trust_id = lease_values.pop('trust_id')
        except KeyError:
            raise exceptions.MissingTrustId()

        # Remove and keep event and reservation values
        events = lease_values.pop("events", [])
        reservations = lease_values.pop("reservations", [])

        # Create the lease without the reservations
        start_date = lease_values['start_date']
        end_date = lease_values['end_date']

        now = datetime.datetime.utcnow()
        now = datetime.datetime(now.year,
                                now.month,
                                now.day,
                                now.hour,
                                now.minute)
        if start_date == 'now':
            start_date = now
        else:
            start_date = self._date_from_string(start_date)
        end_date = self._date_from_string(end_date)

        if start_date < now:
            raise common_ex.NotAuthorized(
                'Start date must later than current date')

        with trusts.create_ctx_from_trust(trust_id) as ctx:
            # NOTE(priteau): We should not get user_id from ctx, because we are
            # in the context of the trustee (blazar user).
            # lease_values['user_id'] is set in blazar/api/v1/service.py
            lease_values['project_id'] = project_id = ctx.project_id
            lease_values['start_date'] = start_date
            lease_values['end_date'] = end_date
            project_name = self._get_project_name(project_id)

            self._check_lease_duration_limit(lease_values, project_name)

            if CONF.manager.usage_enforcement:
                if not CONF.manager.usage_db_host:
                    raise common_ex.ConfigurationError('usage_db_host must be set')
                try:
                    r = redis.StrictRedis(host=CONF.manager.usage_db_host, port=6379, db=0)
                    allocated = r.hget('allocated', project_name)
                    if allocated is None:
                        LOG.info('Setting project %s allocated to %f', CONF.manager.usage_default_allocated)
                        r.hset('allocated', project_name, CONF.manager.usage_default_allocated)
                    balance = r.hget('balance', project_name)
                    if balance is None:
                        LOG.info('Setting project %s balance to %f', CONF.manager.usage_default_allocated)
                        r.hset('balance', project_name, CONF.manager.usage_default_allocated)
                except redis.exceptions.ConnectionError:
                    LOG.exception('Cannot connect to redis server %s', CONF.manager.usage_db_host)

	    events.append({'event_type': 'start_lease',
			   'time': start_date,
			   'status': 'UNDONE'})
	    events.append({'event_type': 'end_lease',
			   'time': end_date,
			   'status': 'UNDONE'})

            before_end_date = lease_values.get('before_end_date', None)
            if before_end_date:
                # incoming param. Validation check
                try:
                    before_end_date = self._date_from_string(
                        before_end_date)
                    self._check_date_within_lease_limits(before_end_date,
                                                         lease_values)
                except common_ex.BlazarException as e:
                    LOG.error("Invalid before_end_date param. %s" % e.message)
                    raise e
            elif CONF.manager.minutes_before_end_lease > 0:
                delta = datetime.timedelta(
                    minutes=CONF.manager.minutes_before_end_lease)
                before_end_date = lease_values['end_date'] - delta

            if before_end_date:
                event = {'event_type': 'before_end_lease',
                         'status': 'UNDONE'}
                events.append(event)
                self._update_before_end_event_date(event, before_end_date,
                                                   lease_values)

            try:
                if trust_id:
                    lease_values.update({'trust_id': trust_id})
                lease = db_api.lease_create(lease_values)
                lease_id = lease['id']
            except db_ex.BlazarDBDuplicateEntry:
                LOG.exception('Cannot create a lease - duplicated lease name')
                raise exceptions.LeaseNameAlreadyExists(
                    name=lease_values['name'])
            except db_ex.BlazarDBException:
                LOG.exception('Cannot create a lease')
                raise
            else:
                try:
                    for reservation in reservations:
                        reservation['lease_id'] = lease['id']
                        reservation['start_date'] = lease['start_date']
                        reservation['end_date'] = lease['end_date']
                        self._create_reservation(reservation,
                                usage_enforcement=CONF.manager.usage_enforcement,
                                usage_db_host=CONF.manager.usage_db_host,
                                project_name=project_name)
                except (exceptions.UnsupportedResourceType,
                        common_ex.BlazarException):
                    LOG.exception("Failed to create reservation for a lease. "
                                  "Rollback the lease and associated "
                                  "reservations")
                    db_api.lease_destroy(lease_id)
                    raise

                try:
                    for event in events:
                        event['lease_id'] = lease['id']
                        db_api.event_create(event)
                except (exceptions.UnsupportedResourceType,
                        common_ex.BlazarException):
                    LOG.exception("Failed to create event for a lease. "
                                  "Rollback the lease and associated "
                                  "reservations")
                    db_api.lease_destroy(lease_id)
                    raise

                else:
                    lease_state = states.LeaseState(id=lease['id'],
                            action=states.lease.CREATE,
                            status=states.lease.COMPLETE,
                            status_reason="Successfully created lease")
                    lease_state.save()
                    lease = db_api.lease_get(lease['id'])
                    self._send_notification(lease, ctx, events=['create'])
                    return lease

    def update_lease(self, lease_id, values):
        if not values:
            return db_api.lease_get(lease_id)

        if len(values) == 1 and 'name' in values:
            db_api.lease_update(lease_id, values)
            return db_api.lease_get(lease_id)

        lease = db_api.lease_get(lease_id)
        start_date = values.get(
            'start_date',
            datetime.datetime.strftime(lease['start_date'], LEASE_DATE_FORMAT))
        end_date = values.get(
            'end_date',
            datetime.datetime.strftime(lease['end_date'], LEASE_DATE_FORMAT))
        before_end_date = values.get('before_end_date', None)

        now = datetime.datetime.utcnow()
        now = datetime.datetime(now.year,
                                now.month,
                                now.day,
                                now.hour,
                                now.minute)
        if start_date == 'now':
            start_date = now
        else:
            start_date = self._date_from_string(start_date)
        if end_date == 'now':
            end_date = now
        else:
            end_date = self._date_from_string(end_date)

        values['start_date'] = start_date
        values['end_date'] = end_date

        if (lease['start_date'] < now and
                values['start_date'] != lease['start_date']):
            raise common_ex.NotAuthorized(
                'Cannot modify the start date of already started leases')

        if (lease['start_date'] > now and
                values['start_date'] < now):
            raise common_ex.NotAuthorized(
                'Start date must later than current date')

        if lease['end_date'] < now:
            raise common_ex.NotAuthorized(
                'Terminated leases can only be renamed')

        if (values['end_date'] < now or
           values['end_date'] < values['start_date']):
            raise common_ex.NotAuthorized(
                'End date must be later than current and start date')

        project_name = self._get_project_name(lease['project_id'])

        with trusts.create_ctx_from_trust(lease['trust_id']) as ctx:
            # To make tests happy...
            try:
                values['project_id'] = lease['project_id']
            except KeyError:
                values['project_id'] = ctx.project_id

            if before_end_date:
                try:
                    before_end_date = self._date_from_string(before_end_date)
                    self._check_date_within_lease_limits(before_end_date,
                                                         values)
                except common_ex.BlazarException as e:
                    LOG.error("Invalid before_end_date param. %s" % e.message)
                    raise e

            started = lease['start_date'] < now and now < lease['end_date']
            self._check_lease_duration_limit(values, project_name, started, lease['end_date'])

            # TODO(frossigneux) rollback if an exception is raised
            for reservation in (
                    db_api.reservation_get_all_by_lease_id(lease_id)):
                reservation['start_date'] = values['start_date']
                reservation['end_date'] = values['end_date']
                resource_type = reservation['resource_type']
                self.plugins[resource_type].update_reservation(
                    reservation['id'],
                    reservation,
                    usage_enforcement=CONF.manager.usage_enforcement,
                    usage_db_host=CONF.manager.usage_db_host,
                    project_name=project_name)

        event = db_api.event_get_first_sorted_by_filters(
            'lease_id',
            'asc',
            {
                'lease_id': lease_id,
                'event_type': 'start_lease'
            }
        )
        if not event:
            raise common_ex.BlazarException(
                'Start lease event not found')
        db_api.event_update(event['id'], {'time': values['start_date']})

        event = db_api.event_get_first_sorted_by_filters(
            'lease_id',
            'asc',
            {
                'lease_id': lease_id,
                'event_type': 'end_lease'
            }
        )
        if not event:
            raise common_ex.BlazarException(
                'End lease event not found')
        db_api.event_update(event['id'], {'time': values['end_date']})

        notifications = ['update']
        self._update_before_end_event(lease, values, notifications,
                                      before_end_date)

        db_api.lease_update(lease_id, values)

        lease_state = states.LeaseState(id=lease_id,
                action=states.lease.UPDATE,
                status=states.lease.COMPLETE,
                status_reason="Successfully updated lease")
        lease_state.save()
        lease = db_api.lease_get(lease_id)
        with trusts.create_ctx_from_trust(lease['trust_id']) as ctx:
            self._send_notification(lease, ctx, events=notifications)

        return lease

    def delete_lease(self, lease_id):
        lease = self.get_lease(lease_id)
        project_name = self._get_project_name(lease['project_id'])
        if (datetime.datetime.utcnow() >= lease['start_date'] and
                datetime.datetime.utcnow() <= lease['end_date']):
            start_event = db_api.event_get_first_sorted_by_filters(
                'lease_id',
                'asc',
                {
                    'lease_id': lease_id,
                    'event_type': 'start_lease',
                    'status': 'DONE'
                }
            )
            if not start_event:
                raise common_ex.BlazarException('Invalid event status')
            end_event = db_api.event_get_first_sorted_by_filters(
                'lease_id',
                'asc',
                {
                    'lease_id': lease_id,
                    'event_type': 'end_lease',
                    'status': 'UNDONE'
                }
            )
            if not end_event:
                raise common_ex.BlazarException('Invalid event status')
            db_api.event_update(end_event['id'], {'status': 'IN_PROGRESS'})

        with trusts.create_ctx_from_trust(lease['trust_id']) as ctx:
            for reservation in lease['reservations']:
                if reservation['status'] != 'deleted':
                    plugin = self.plugins[reservation['resource_type']]
                    try:
                        plugin.on_end(reservation['resource_id'],
                                      usage_enforcement=CONF.manager.usage_enforcement,
                                      usage_db_host=CONF.manager.usage_db_host,
                                      project_name=project_name)
                    except (db_ex.BlazarDBException, RuntimeError):
                        LOG.exception("Failed to delete a reservation "
                                      "for a lease.")
                        lease_state = states.LeaseState(id=lease_id,
                            action=states.lease.DELETE,
                            status=states.lease.FAILED,
                            status_reason=error_msg)
                        lease_state.save()
                        raise
            db_api.lease_destroy(lease_id)
            self._send_notification(lease, ctx, events=['delete'])

    def start_lease(self, lease_id, event_id):
        lease = self.get_lease(lease_id)
        with trusts.create_ctx_from_trust(lease['trust_id']):
            self._basic_action(lease_id, event_id, 'on_start', 'active')

    def end_lease(self, lease_id, event_id):
        lease = self.get_lease(lease_id)
        for reservation in lease['reservations']:
            db_api.reservation_update(reservation['id'],
                                      {'status': 'completed'})
        with trusts.create_ctx_from_trust(lease['trust_id']):
            self._basic_action(lease_id, event_id, 'on_end', 'deleted')

    def before_end_lease(self, lease_id, event_id):
        lease = self.get_lease(lease_id)
        with trusts.create_ctx_from_trust(lease['trust_id']):
            self._basic_action(lease_id, event_id, 'before_end')

    def _basic_action(self, lease_id, event_id, action_time,
                      reservation_status=None):
        """Commits basic lease actions such as starting and ending."""
        lease = self.get_lease(lease_id)

        event_status = 'DONE'

        if action_time == 'on_start':
            lease_action = states.lease.START
            status_reason = "Starting lease..."
        elif action_time == 'on_end':
            lease_action = states.lease.STOP
            status_reason = "Stopping lease..."
        else:
            raise AttributeError("action_time is %s instead of either on_start or on_end"
                                 % action_time)

        lease_state = states.LeaseState(id=lease_id, action=lease_action,
                status=states.lease.IN_PROGRESS,
                status_reason=status_reason)
        lease_state.save()

        for reservation in lease['reservations']:
            resource_type = reservation['resource_type']
            try:
                self.resource_actions[resource_type][action_time](
                    reservation['resource_id']
                )
            except common_ex.BlazarException:
                LOG.exception("Failed to execute action %(action)s "
                              "for lease %(lease)s"
                              % {
                                  'action': action_time,
                                  'lease': lease_id,
                              })
                event_status = 'ERROR'
                db_api.reservation_update(reservation['id'],
                                          {'status': 'error'})
            else:
                if reservation_status is not None:
                    db_api.reservation_update(reservation['id'],
                                              {'status': reservation_status})

        db_api.event_update(event_id, {'status': event_status})

        if event_status == 'DONE':
            lease_status = states.lease.COMPLETE
            if action_time ==  'on_start':
                status_reason = "Successfully started lease"
            elif action_time == 'on_end':
                status_reason = "Successfully stopped lease"
            else:
                raise AttributeError("action_time is %s instead of either on_start or on_end"
                                     % action_time)
        elif event_status == 'ERROR':
            lease_status = states.lease.FAILED
            if action_time ==  'on_start':
                status_reason = "Failed to start lease"
            elif action_time == 'on_end':
                status_reason = "Failed to stop lease"
            else:
                raise AttributeError("action_time is %s instead of either on_start or on_end"
                                     % action_time)
        else:
            raise AttributeError("event_status is %s instead of either DONE or ERROR"
                                 % event_status)

        lease_state.update(action=lease_action,
                           status=lease_status,
                           status_reason=status_reason)
        lease_state.save()

    def _create_reservation(self, values, usage_enforcement=None, usage_db_host=None, user_name=None, project_name=None):
        resource_type = values['resource_type']
        if resource_type not in self.plugins:
            raise exceptions.UnsupportedResourceType(resource_type)
        reservation_values = {
            'lease_id': values['lease_id'],
            'resource_type': resource_type,
            'status': 'pending'
        }
        reservation = db_api.reservation_create(reservation_values)
        resource_id = self.plugins[resource_type].reserve_resource(
            reservation['id'],
            values,
            usage_enforcement=usage_enforcement,
            usage_db_host=usage_db_host,
            user_name=user_name,
            project_name=project_name
        )
        db_api.reservation_update(reservation['id'],
                                  {'resource_id': resource_id})

    def _send_notification(self, lease, ctx, events=[]):
        payload = notification_api.format_lease_payload(lease)

        for event in events:
            notification_api.send_lease_notification(ctx, payload,
                                                     'lease.%s' % event)

    def _check_date_within_lease_limits(self, date, lease):
        if not lease['start_date'] < date < lease['end_date']:
            raise common_ex.NotAuthorized(
                'Datetime is out of lease limits')

    def _update_before_end_event_date(self, event, before_end_date, lease):
        event['time'] = before_end_date
        if event['time'] < lease['start_date']:
            LOG.warning("Start_date greater than before_end_date. "
                        "Setting before_end_date to %s for lease %s"
                        % (lease['start_date'], lease.get('id',
                           lease.get('name'))))
            event['time'] = lease['start_date']

    def _update_before_end_event(self, old_lease, new_lease,
                                 notifications, before_end_date=None):
        event = db_api.event_get_first_sorted_by_filters(
            'lease_id',
            'asc',
            {
                'lease_id': old_lease['id'],
                'event_type': 'before_end_lease'
            }
        )
        if event:
            # NOTE(casanch1) do nothing if the event does not exist.
            # This is for backward compatibility
            update_values = {}
            if not before_end_date:
                # before_end_date needs to be calculated based on
                # previous delta
                prev_before_end_delta = old_lease['end_date'] - event['time']
                before_end_date = new_lease['end_date'] - prev_before_end_delta

            self._update_before_end_event_date(update_values, before_end_date,
                                               new_lease)
            if event['status'] == 'DONE':
                update_values['status'] = 'UNDONE'
                notifications.append('event.before_end_lease.stop')

            db_api.event_update(event['id'], update_values)

    def __getattr__(self, name):
        """RPC Dispatcher for plugins methods."""

        fn = None
        try:
            resource_type, method = name.rsplit(':', 1)
        except ValueError:
            # NOTE(sbauza) : the dispatcher needs to know which plugin to use,
            #  raising error if consequently not
            raise AttributeError(name)
        try:
            try:
                fn = getattr(self.plugins[resource_type], method)
            except KeyError:
                LOG.error("Plugin with resource type %s not found",
                          resource_type)
                raise exceptions.UnsupportedResourceType(resource_type)
        except AttributeError:
            LOG.error("Plugin %s doesn't include method %s",
                      self.plugins[resource_type], method)
        if fn is not None:
            return fn
        raise AttributeError(name)
