# -*- coding: utf-8 -*-
#
# Author: François Rossigneux <francois.rossigneux@inria.fr>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime
from random import shuffle

from keystoneauth1 import identity
from keystoneauth1 import session
from neutronclient.v2_0 import client as neutron_client
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import strutils

from blazar.db import api as db_api
from blazar.db import exceptions as db_ex
from blazar.db import utils as db_utils
from blazar.manager import exceptions as manager_ex
from blazar.plugins import base
from blazar.plugins import networks as plugin
from blazar import status
from blazar.utils.openstack import keystone
from blazar.utils.openstack import nova
from blazar.utils import plugins as plugins_utils

plugin_opts = [
    cfg.StrOpt('before_end',
               default='',
               help='Actions which we will be taken before the end of '
                    'the lease'),
]

CONF = cfg.CONF
CONF.register_opts(plugin_opts, group=plugin.RESOURCE_TYPE)
LOG = logging.getLogger(__name__)


before_end_options = ['', 'snapshot', 'default', 'email']


class PhysicalNetworkPlugin(base.BasePlugin, nova.NovaClientWrapper):
    """Plugin for physical network resource."""
    resource_type = plugin.RESOURCE_TYPE
    title = 'Physical Network Plugin'
    description = 'This plugin starts and shutdowns the networks.'
    freepool_name = CONF.nova.aggregate_freepool_name
    pool = None

    def __init__(self):
        super(PhysicalNetworkPlugin, self).__init__(
            username=CONF.os_admin_username,
            password=CONF.os_admin_password,
            user_domain_name=CONF.os_admin_user_domain_name,
            project_name=CONF.os_admin_project_name,
            project_domain_name=CONF.os_admin_project_domain_name)
        self.usage_enforcer = None

    def set_usage_enforcer(self, usage_enforcer):
        self.usage_enforcer = usage_enforcer

    def reserve_resource(self, reservation_id, values):
        """Create reservation."""
        self._check_params(values)

        lease = db_api.lease_get(values['lease_id'])
        network_ids = self._matching_networks(
            values['resource_properties'],
            values['start_date'],
            values['end_date'],
        )
        if not network_ids:
            raise manager_ex.NotEnoughNetworksAvailable()

        # NOTE(priteau): Check if we have enough available SUs for this
        # reservation. This takes into account the su_factor of each allocated
        # network, if present.
###        try:
###            self.usage_enforcer.check_usage_against_allocation(
###                lease, allocated_network_ids=network_ids)
###        except manager_ex.RedisConnectionError:
###            pass

        network_rsrv_values = {
            'reservation_id': reservation_id,
            'resource_properties': values['resource_properties'],
            'status': 'pending',
            'before_end': values['before_end'],
            'network_name': values['network_name']
        }
        network_reservation = db_api.network_reservation_create(
            network_rsrv_values)
        for network_id in network_ids:
            db_api.network_allocation_create({
                'network_id': network_id, 'reservation_id': reservation_id})
        return network_reservation['id']

    def update_reservation(self, reservation_id, values):
        """Update reservation."""
        reservation = db_api.reservation_get(reservation_id)
        lease = db_api.lease_get(reservation['lease_id'])

        if (not [x for x in values.keys() if x in ['min', 'max',
                                                   'network_properties',
                                                   'resource_properties']]
                and values['start_date'] >= lease['start_date']
                and values['end_date'] <= lease['end_date']):
            # Nothing to update
            return

        # Check if we have enough available SUs for update
        network_allocations = db_api.network_allocation_get_all_by_values(
            reservation_id=reservation_id)
###        try:
###            self.usage_enforcer.check_usage_against_allocation_pre_update(
###                values, lease, network_allocations)
###        except manager_ex.RedisConnectionError:
###            pass

        dates_before = {'start_date': lease['start_date'],
                        'end_date': lease['end_date']}
        dates_after = {'start_date': values['start_date'],
                       'end_date': values['end_date']}
        network_reservation = db_api.network_reservation_get(
            reservation['resource_id'])
        self._update_allocations(dates_before, dates_after, reservation_id,
                                 reservation['status'], network_reservation,
                                 values, lease)

        updates = {}
        if 'min' in values or 'max' in values:
            count_range = str(values.get(
                'min', network_reservation['count_range'].split('-')[0])
            ) + '-' + str(values.get(
                'max', network_reservation['count_range'].split('-')[1])
            )
            updates['count_range'] = count_range
        if 'network_properties' in values:
            updates['network_properties'] = values.get(
                'network_properties')
        if 'resource_properties' in values:
            updates['resource_properties'] = values.get(
                'resource_properties')
        if updates:
            db_api.network_reservation_update(network_reservation['id'], updates)

    def on_start(self, resource_id):
        """Creates a Neutron network using the allocated segment."""
        network_reservation = db_api.network_reservation_get(resource_id)
        network_name = network_reservation['network_name']
        reservation_id = network_reservation['reservation_id']

        # We need the lease to get to the trust_id
        reservation = db_api.reservation_get(reservation_id)
        lease = db_api.lease_get(reservation['lease_id'])

        for allocation in db_api.network_allocation_get_all_by_values(
                reservation_id=reservation_id):
            network_segment = db_api.network_get(allocation['network_id'])
            network_type = network_segment['network_type']
            physical_network = network_segment['physical_network']
            segment_id = network_segment['segment_id']
            auth_url = "%s://%s:%s/%s" % (CONF.os_auth_protocol,
                                          CONF.os_auth_host,
                                          CONF.os_auth_port,
                                          CONF.os_auth_prefix)
            self.auth = identity.Password(
                auth_url=auth_url,
                username=CONF.os_admin_username,
                password=CONF.os_admin_password,
                project_domain_name=CONF.os_admin_project_domain_name,
                user_domain_name=CONF.os_admin_user_domain_name,
                trust_id=lease['trust_id'])
            self.sess = session.Session(auth=self.auth)
            self.neutron = neutron_client.Client(
                session=self.sess, region_name=CONF.os_region_name)
            network_body = {
                "network": {
                    "name": network_name,
                    "provider:network_type": network_type,
                    "provider:segmentation_id": segment_id,
                }
            }
            if physical_network:
                network_body['network']['provider:physical_network'] = physical_network

            try:
                netw = self.neutron.create_network(body=network_body)
                net_dict = netw['network']
                network_id = net_dict['id']
                db_api.network_reservation_update(network_reservation['id'],
                                                  {'network_id': network_id})
            except Exception:
                LOG.error("Failed to create Neutron network %s", network_name)
                raise
                #raise manager_ex.NetworkCreationFailed(name=network_name,
                #                                       id=reservation_id)

    def delete_neutron_network(self, network_id, reservation_id, trust_id):
        auth_url = "%s://%s:%s/%s" % (CONF.os_auth_protocol,
                                      CONF.os_auth_host,
                                      CONF.os_auth_port,
                                      CONF.os_auth_prefix)
        self.auth = identity.Password(
            auth_url=auth_url,
            username=CONF.os_admin_username,
            password=CONF.os_admin_password,
            project_domain_name=CONF.os_admin_project_domain_name,
            user_domain_name=CONF.os_admin_user_domain_name,
            trust_id=trust_id)
        self.sess = session.Session(auth=self.auth)
        self.neutron = neutron_client.Client(
            session=self.sess, region_name=CONF.os_region_name)
        try:
            self.neutron.delete_network(network_id)
        except Exception:
            raise manager_ex.NetworkDeletionFailed(
                network_id=network_id, reservation_id=reservation_id)

    def on_end(self, resource_id):
        """
        Delete the Neutron network created on start and associated Neutron
        resources.
        """
        network_reservation = db_api.network_reservation_get(resource_id)
        reservation_id = network_reservation['reservation_id']

        # We need the lease to get to the trust_id
        reservation = db_api.reservation_get(reservation_id)
        lease = db_api.lease_get(reservation['lease_id'])
        trust_id = lease['trust_id']
        db_api.network_reservation_update(network_reservation['id'],
                                          {'status': 'completed'})
        allocations = db_api.network_allocation_get_all_by_values(
            reservation_id=network_reservation['reservation_id'])
        for allocation in allocations:
            db_api.network_allocation_destroy(allocation['id'])
        network_id = network_reservation['network_id']

        self.delete_neutron_network(network_id, reservation_id, trust_id)

        reservation = db_api.reservation_get(
            network_reservation['reservation_id'])
        lease = db_api.lease_get(reservation['lease_id'])
        try:
            self.usage_enforcer.release_encumbered(
                lease, reservation, allocations)
        except manager_ex.RedisConnectionError:
            pass

    def heal_reservations(self, failed_resources, interval_begin,
                          interval_end):
        """Heal reservations which suffer from resource failures.

        :param: failed_resources: a list of failed networks.
        :param: interval_begin: start date of the period to heal.
        :param: interval_end: end date of the period to heal.
        :return: a dictionary of {reservation id: flags to update}
                 e.g. {'de27786d-bd96-46bb-8363-19c13b2c6657':
                       {'missing_resources': True}}
        """
        reservation_flags = {}

        network_ids = [h['id'] for h in failed_resources]
        reservations = db_utils.get_reservations_by_network_ids(network_ids,
                                                             interval_begin,
                                                             interval_end)

        for reservation in reservations:
            if reservation['resource_type'] != plugin.RESOURCE_TYPE:
                continue

            for allocation in [alloc for alloc
                               in reservation['computenetwork_allocations']
                               if alloc['compute_network_id'] in network_ids]:
                if self._reallocate(allocation):
                    if reservation['status'] == status.reservation.ACTIVE:
                        if reservation['id'] not in reservation_flags:
                            reservation_flags[reservation['id']] = {}
                        reservation_flags[reservation['id']].update(
                            {'resources_changed': True})
                else:
                    if reservation['id'] not in reservation_flags:
                        reservation_flags[reservation['id']] = {}
                    reservation_flags[reservation['id']].update(
                        {'missing_resources': True})

        return reservation_flags

    def _reallocate(self, allocation):
        """Allocate an alternative network.

        :param: allocation: allocation to change.
        :return: True if an alternative network was successfully allocated.
        """
        reservation = db_api.reservation_get(allocation['reservation_id'])
        h_reservation = db_api.network_reservation_get(
            reservation['resource_id'])
        lease = db_api.lease_get(reservation['lease_id'])
        pool = nova.ReservationPool()

        # Remove the old network from the aggregate.
        if reservation['status'] == status.reservation.ACTIVE:
            network = db_api.network_get(allocation['compute_network_id'])
            pool.remove_network(h_reservation['aggregate_id'],
                                    network['hypervisor_networkname'])

        # Allocate an alternative network.
        start_date = max(datetime.datetime.utcnow(), lease['start_date'])
        new_networkids = self._matching_networks(
            reservation['network_properties'],
            reservation['resource_properties'],
            '1-1', start_date, lease['end_date']
        )
        if not new_networkids:
            db_api.network_allocation_destroy(allocation['id'])
            LOG.warn('Could not find alternative network for reservation %s '
                     '(lease: %s).', reservation['id'], lease['name'])
            return False
        else:
            new_networkid = new_networkids.pop()
            db_api.network_allocation_update(allocation['id'],
                                          {'compute_network_id': new_networkid})
            LOG.warn('Resource changed for reservation %s (lease: %s).',
                     reservation['id'], lease['name'])
            if reservation['status'] == status.reservation.ACTIVE:
                # Add the alternative network into the aggregate.
                new_network = db_api.network_get(new_networkid)
                pool.add_network(h_reservation['aggregate_id'],
                                     new_network['hypervisor_networkname'])

            return True

    def _get_extra_capabilities(self, network_id):
        extra_capabilities = {}
        raw_extra_capabilities = (
            db_api.network_extra_capability_get_all_per_network(network_id))
        for capability in raw_extra_capabilities:
            key = capability['capability_name']
            extra_capabilities[key] = capability['capability_value']
        return extra_capabilities

    def get_network(self, network_id):
        network = db_api.network_get(network_id)
        return network

    def list_networks(self):
        raw_network_list = db_api.network_list()
        network_list = []
        for network in raw_network_list:
            network_list.append(self.get_network(network['id']))
        return network_list

    def validate_network_param(self, values):
        marshall_attributes = set(['network_type', 'physical_network',
                                   'segment_id'])
        missing_attr = marshall_attributes - set(values.keys())
        if missing_attr:
            raise manager_ex.MissingParameter(param=','.join(missing_attr))

    def create_network(self, values):
        self.validate_network_param(values)
        network_type = values.get('network_type')
        physical_network = values.get('physical_network')
        segment_id = values.get('segment_id')
        if network_type == 'vlan':
            try:
                segment_id = int(segment_id)
            except ValueError:
                raise manager_ex.MalformedParameter(param=segment_id)
            if segment_id < 1 or segment_id > 4094:
                raise manager_ex.MalformedParameter(param=segment_id)

        network_values = {
            'network_type': network_type,
            'physical_network': physical_network,
            'segment_id': segment_id
        }
        network = db_api.network_create(network_values)
        return self.get_network(network['id'])

    def is_updatable_extra_capability(self, capability):
        reservations = db_utils.get_reservations_by_network_id(
            capability['computenetwork_id'], datetime.datetime.utcnow(),
            datetime.date.max)

        for r in reservations:
            plugin_reservation = db_utils.get_plugin_reservation(
                r['resource_type'], r['resource_id'])

            requirements_queries = plugins_utils.convert_requirements(
                plugin_reservation['resource_properties'])

            # TODO(masahito): If all the reservations using the
            # extra_capability can be re-allocated it's okay to update
            # the extra_capability.
            for requirement in requirements_queries:
                # A requirement is of the form "key op value" as string
                if requirement.split(" ")[0] == capability['capability_name']:
                    return False
        return True

    def update_network(self, network_id, values):
        network = db_api.network_get(network_id)
        if not network:
            raise manager_ex.NetworkNotFound(network=network_id)

        updatable = ['network_type', 'physical_network', 'segment_id']
        for key in values.keys():
            if key not in updatable:
                raise manager_ex.MalformedParameter(param=key)

        network_type = values.get('network_type')
        if network_type == 'vlan':
            segment_id = values.get('segment_id')
            if segment_id is not None:
                try:
                    segment_id = int(segment_id)
                except ValueError:
                    raise manager_ex.MalformedParameter(param=segment_id)
                if segment_id < 1 or segment_id > 4094:
                    raise manager_ex.MalformedParameter(param=segment_id)

        new_values = {}
        for key in updatable:
            if key in values and values[key] is not None:
                new_values[key] = values[key]
        return db_api.network_update(network_id, new_values)

    def delete_network(self, network_id):
        network = db_api.network_get(network_id)
        if not network:
            raise manager_ex.NetworkNotFound(network=network_id)

        if db_api.network_allocation_get_all_by_values(
                compute_network_id=network_id):
            raise manager_ex.CantDeleteNetwork(
                network=network_id,
                msg='The network is reserved.'
            )

#        inventory = nova.NovaInventory()
#        servers = inventory.get_servers_per_network(
#            network['hypervisor_networkname'])
#        if servers:
#            raise manager_ex.HostHavingServers(
#                network=network['hypervisor_networkname'], servers=servers)
#
        try:
            db_api.network_destroy(network_id)
        except db_ex.BlazarDBException as e:
            # Nothing so bad, but we need to alert admins
            # they have to rerun
            raise manager_ex.CantDeleteNetwork(network=network_id, msg=str(e))

    def _matching_networks(self, resource_properties, start_date, end_date):
        """Return the matching networks (preferably not allocated)"""
        allocated_network_ids = []
        not_allocated_network_ids = []
        filter_array = []
        start_date_with_margin = start_date - datetime.timedelta(
            minutes=CONF.cleaning_time)
        end_date_with_margin = end_date + datetime.timedelta(
            minutes=CONF.cleaning_time)

        # TODO(frossigneux) support "or" operator
        if resource_properties:
            filter_array += plugins_utils.convert_requirements(
                resource_properties)
        for network in db_api.reservable_network_get_all_by_queries(
                filter_array):
            if not db_api.network_allocation_get_all_by_values(
                    network_id=network['id']):
                not_allocated_network_ids.append(network['id'])
            elif db_utils.get_free_periods(
                network['id'],
                start_date_with_margin,
                end_date_with_margin,
                end_date_with_margin - start_date_with_margin
            ) == [
                (start_date_with_margin, end_date_with_margin),
            ]:
                allocated_network_ids.append(network['id'])
        if len(not_allocated_network_ids) >= 1:
            shuffle(not_allocated_network_ids)
            return not_allocated_network_ids[:1]
        all_network_ids = allocated_network_ids + not_allocated_network_ids
        if len(all_network_ids) >= 1:
            shuffle(all_network_ids)
            return all_network_ids[:1]
        else:
            return []

    def _convert_int_param(self, param, name):
        """Checks that the parameter is present and can be converted to int."""
        if param is None:
            raise manager_ex.MissingParameter(param=name)
        if strutils.is_int_like(param):
            param = int(param)
        else:
            raise manager_ex.MalformedParameter(param=name)
        return param

    def _check_params(self, values):
        if 'resource_properties' not in values:
            raise manager_ex.MissingParameter(param='resource_properties')

        if 'before_end' not in values:
            values['before_end'] = 'default'
        if values['before_end'] not in before_end_options:
            raise manager_ex.MalformedParameter(param='before_end')

    def _update_allocations(self, dates_before, dates_after, reservation_id,
                            reservation_status, network_reservation, values,
                            lease):
        min_networks = self._convert_int_param(values.get(
            'min', network_reservation['count_range'].split('-')[0]), 'min')
        max_networks = self._convert_int_param(values.get(
            'max', network_reservation['count_range'].split('-')[1]), 'max')
        if min_networks < 0 or max_networks < min_networks:
            raise manager_ex.InvalidRange()
        network_properties = values.get(
            'network_properties',
            network_reservation['network_properties'])
        resource_properties = values.get(
            'resource_properties',
            network_reservation['resource_properties'])
        allocs = db_api.network_allocation_get_all_by_values(
            reservation_id=reservation_id)

        allocs_to_remove = self._allocations_to_remove(
            dates_before, dates_after, max_networks, network_properties,
            resource_properties, allocs)

        if (allocs_to_remove and
                reservation_status == status.reservation.ACTIVE):
            raise manager_ex.NotEnoughHostsAvailable()

        kept_networks = len(allocs) - len(allocs_to_remove)
        network_ids_to_add = []
        if kept_networks < max_networks:
            min_networks = min_networks - kept_networks \
                if (min_networks - kept_networks) > 0 else 0
            max_networks = max_networks - kept_networks
            network_ids_to_add = self._matching_networks(
                network_properties, resource_properties,
                str(min_networks) + '-' + str(max_networks),
                dates_after['start_date'], dates_after['end_date'])

            if len(network_ids_to_add) < min_networks:
                raise manager_ex.NotEnoughHostsAvailable()

        allocs_to_keep = [a for a in allocs if a not in allocs_to_remove]
        allocs_to_add = [{'compute_network_id': h} for h in network_ids_to_add]
        new_allocations = allocs_to_keep + allocs_to_add

###        try:
###            self.usage_enforcer.check_usage_against_allocation_post_update(
###                values, lease,
###                allocs,
###                new_allocations)
###        except manager_ex.RedisConnectionError:
###            pass

        for network_id in network_ids_to_add:
            LOG.debug('Adding network {} to reservation {}'.format(
                network_id, reservation_id))
            db_api.network_allocation_create(
                {'compute_network_id': network_id,
                 'reservation_id': reservation_id})

        for allocation in allocs_to_remove:
            LOG.debug('Removing network {} from reservation {}'.format(
                allocation['compute_network_id'], reservation_id))
            db_api.network_allocation_destroy(allocation['id'])

    def _allocations_to_remove(self, dates_before, dates_after, max_networks,
                               network_properties, resource_properties,
                               allocs):
        """Finds candidate compute network allocations to remove"""
        allocs_to_remove = []
        requested_network_ids = [network['id'] for network in
                              self._filter_networks_by_properties(
                                  network_properties, resource_properties)]

        for alloc in allocs:
            if alloc['compute_network_id'] not in requested_network_ids:
                allocs_to_remove.append(alloc)
                continue
            if (dates_before['start_date'] > dates_after['start_date'] or
                    dates_before['end_date'] < dates_after['end_date']):
                reserved_periods = db_utils.get_reserved_periods(
                    alloc['compute_network_id'],
                    dates_after['start_date'],
                    dates_after['end_date'],
                    datetime.timedelta(seconds=1))

                max_start = max(dates_before['start_date'],
                                dates_after['start_date'])
                min_end = min(dates_before['end_date'],
                              dates_after['end_date'])

                if not (len(reserved_periods) == 0 or
                        (len(reserved_periods) == 1 and
                         reserved_periods[0][0] == max_start and
                         reserved_periods[0][1] == min_end)):
                    allocs_to_remove.append(alloc)
                    continue

        kept_networks = len(allocs) - len(allocs_to_remove)
        if kept_networks > max_networks:
            allocs_to_remove.extend(
                [allocation for allocation in allocs
                 if allocation not in allocs_to_remove
                 ][:(kept_networks - max_networks)]
            )

        return allocs_to_remove

    def _filter_networks_by_properties(self, network_properties,
                                    resource_properties):
        filter = []
        if network_properties:
            filter += plugins_utils.convert_requirements(network_properties)
        if resource_properties:
            filter += plugins_utils.convert_requirements(resource_properties)
        if filter:
            return db_api.network_get_all_by_queries(filter)
        else:
            return db_api.network_list()


class PhysicalHostMonitorPlugin(base.BaseMonitorPlugin,
                                nova.NovaClientWrapper):
    """Monitor plugin for physical network resource."""

    # Singleton design pattern
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(PhysicalHostMonitorPlugin, cls).__new__(cls)
            cls._instance.healing_handlers = []
            super(PhysicalHostMonitorPlugin, cls._instance).__init__(
                username=CONF.os_admin_username,
                password=CONF.os_admin_password,
                user_domain_name=CONF.os_admin_user_domain_name,
                project_name=CONF.os_admin_project_name,
                project_domain_name=CONF.os_admin_project_domain_name)
        return cls._instance

    def __init__(self):
        """Do nothing.

        This class uses the Singleton design pattern and an instance of this
        class is generated and initialized in __new__().
        """
        pass

    def register_healing_handler(self, handler):
        self.healing_handlers.append(handler)

    def is_notification_enabled(self):
        """Check if the notification monitor is enabled."""
        return CONF[plugin.RESOURCE_TYPE].enable_notification_monitor

    def get_notification_event_types(self):
        """Get event types of notification messages to handle."""
        return ['service.update']

    def get_notification_topics(self):
        """Get topics of notification to subscribe to."""
        return CONF[plugin.RESOURCE_TYPE].notification_topics

    def notification_callback(self, event_type, payload):
        """Handle a notification message.

        It is used as a callback of a notification-based resource monitor.

        :param event_type: an event type of a notification.
        :param payload: a payload of a notification.
        :return: a dictionary of {reservation id: flags to update}
                 e.g. {'de27786d-bd96-46bb-8363-19c13b2c6657':
                       {'missing_resources': True}}
        """
        LOG.trace('Handling a notification...')
        reservation_flags = {}

        data = payload.get('nova_object.data', None)
        if data:
            if data['disabled'] or data['forced_down']:
                failed_networks = db_api.reservable_network_get_all_by_queries(
                    ['hypervisor_networkname == ' + data['network']])
                if failed_networks:
                    LOG.warn('%s failed.',
                             failed_networks[0]['hypervisor_networkname'])
                    reservation_flags = self._handle_failures(failed_networks)
            else:
                recovered_networks = db_api.network_get_all_by_queries(
                    ['reservable == 0',
                     'hypervisor_networkname == ' + data['network']])
                if recovered_networks:
                    db_api.network_update(recovered_networks[0]['id'],
                                       {'reservable': True})
                    LOG.warn('%s recovered.',
                             recovered_networks[0]['hypervisor_networkname'])

        return reservation_flags

    def is_polling_enabled(self):
        """Check if the polling monitor is enabled."""
        return CONF[plugin.RESOURCE_TYPE].enable_polling_monitor

    def get_polling_interval(self):
        """Get interval of polling."""
        return CONF[plugin.RESOURCE_TYPE].polling_interval

    def poll(self):
        """Detect and handle resource failures.

        :return: a dictionary of {reservation id: flags to update}
                 e.g. {'de27786d-bd96-46bb-8363-19c13b2c6657':
                 {'missing_resources': True}}
        """
        LOG.trace('Poll...')
        reservation_flags = {}

        failed_networks, recovered_networks = self._poll_resource_failures()
        if failed_networks:
            for network in failed_networks:
                LOG.warn('%s failed.', network['hypervisor_networkname'])
            reservation_flags = self._handle_failures(failed_networks)
        if recovered_networks:
            for network in recovered_networks:
                db_api.network_update(network['id'], {'reservable': True})
                LOG.warn('%s recovered.', network['hypervisor_networkname'])

        return reservation_flags

    def _poll_resource_failures(self):
        """Check health of networks by calling Nova Hypervisors API.

        :return: a list of failed networks, a list of recovered networks.
        """
        networks = db_api.network_get_all_by_filters({})
        reservable_networks = [h for h in networks if h['reservable'] is True]
        unreservable_networks = [h for h in networks if h['reservable'] is False]

        try:
            hvs = self.nova.hypervisors.list()

            failed_hv_ids = [str(hv.id) for hv in hvs
                             if hv.state == 'down' or hv.status == 'disabled']
            failed_networks = [network for network in reservable_networks
                            if network['id'] in failed_hv_ids]

            active_hv_ids = [str(hv.id) for hv in hvs
                             if hv.state == 'up' and hv.status == 'enabled']
            recovered_networks = [network for network in unreservable_networks
                               if network['id'] in active_hv_ids]
        except Exception as e:
            LOG.exception('Skipping health check. %s', str(e))

        return failed_networks, recovered_networks

    def _handle_failures(self, failed_networks):
        """Handle resource failures.

        :param: failed_networks: a list of failed networks.
        :return: a dictionary of {reservation id: flags to update}
                 e.g. {'de27786d-bd96-46bb-8363-19c13b2c6657':
                 {'missing_resources': True}}
        """

        # Update the computenetworks table
        for network in failed_networks:
            try:
                db_api.network_update(network['id'], {'reservable': False})
            except Exception as e:
                LOG.exception('Failed to update %s. %s',
                              network['hypervisor_networkname'], str(e))

        # Heal related reservations
        return self.heal()

    def get_healing_interval(self):
        """Get interval of reservation healing in minutes."""
        return CONF[plugin.RESOURCE_TYPE].healing_interval

    def heal(self):
        """Heal suffering reservations in the next healing interval.

        :return: a dictionary of {reservation id: flags to update}
        """
        reservation_flags = {}
        networks = db_api.unreservable_network_get_all_by_queries([])

        interval_begin = datetime.datetime.utcnow()
        interval = self.get_healing_interval()
        if interval == 0:
            interval_end = datetime.date.max
        else:
            interval_end = interval_begin + datetime.timedelta(
                minutes=interval)

        for handler in self.healing_handlers:
            reservation_flags.update(handler(networks,
                                             interval_begin,
                                             interval_end))

        return reservation_flags
