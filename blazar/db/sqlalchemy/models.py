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


from oslo_utils import uuidutils
import six
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import relationship

from blazar.db.sqlalchemy import model_base as mb

# Helpers


def _generate_unicode_uuid():
    return six.text_type(uuidutils.generate_uuid())


def MediumText():
    return sa.Text().with_variant(MEDIUMTEXT(), 'mysql')


def _id_column():
    return sa.Column(sa.String(36),
                     primary_key=True,
                     default=_generate_unicode_uuid)


# Main objects: Lease, Reservation, Event

class Lease(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """Contains all info about lease."""

    __tablename__ = 'leases'

    id = _id_column()
    name = sa.Column(sa.String(80), nullable=False)
    user_id = sa.Column(sa.String(255), nullable=True)
    project_id = sa.Column(sa.String(255), nullable=True)
    start_date = sa.Column(sa.DateTime, nullable=False)
    end_date = sa.Column(sa.DateTime, nullable=False)
    trust_id = sa.Column(sa.String(36))
    reservations = relationship('Reservation', cascade="all,delete",
                                backref='lease', lazy='joined')
    events = relationship('Event', cascade="all,delete",
                          backref='lease', lazy='joined')
    status = sa.Column(sa.String(255))
    degraded = sa.Column(sa.Boolean, nullable=False,
                         server_default=sa.false())

    def to_dict(self):
        d = super(Lease, self).to_dict()
        d['reservations'] = [r.to_dict() for r in self.reservations]
        d['events'] = [e.to_dict() for e in self.events]
        return d


class Reservation(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """Specifies group of nodes within a cluster."""

    __tablename__ = 'reservations'

    id = _id_column()
    lease_id = sa.Column(sa.String(36),
                         sa.ForeignKey('leases.id'),
                         nullable=False)
    resource_id = sa.Column(sa.String(36))
    resource_type = sa.Column(sa.String(66))
    status = sa.Column(sa.String(13))
    missing_resources = sa.Column(sa.Boolean, nullable=False,
                                  server_default=sa.false())
    resources_changed = sa.Column(sa.Boolean, nullable=False,
                                  server_default=sa.false())
    instance_reservation = relationship('InstanceReservations',
                                        uselist=False,
                                        cascade='all,delete',
                                        backref='reservation',
                                        lazy='joined')
    computehost_reservation = relationship('ComputeHostReservation',
                                           uselist=False,
                                           cascade="all,delete",
                                           backref='reservation',
                                           lazy='joined')
    computehost_allocations = relationship('ComputeHostAllocation',
                                           uselist=True,
                                           cascade="all,delete",
                                           backref='reservation',
                                           lazy='joined')

    def to_dict(self):
        d = super(Reservation, self).to_dict()

        if self.computehost_reservation:

            res = self.computehost_reservation.to_dict()
            d['hypervisor_properties'] = res['hypervisor_properties']
            d['resource_properties'] = res['resource_properties']
            d['before_end'] = res['before_end']

            if res['count_range']:
                try:
                    minMax = res['count_range'].split('-', 1)
                    (d['min'], d['max']) = map(int, minMax)
                except ValueError:
                    e = "Invalid count range: {0}".format(res['count_range'])
                    raise RuntimeError(e)

        if self.instance_reservation:
            ir_keys = ['vcpus', 'memory_mb', 'disk_gb', 'amount', 'affinity',
                       'flavor_id', 'aggregate_id', 'server_group_id',
                       'resource_properties']
            d.update(self.instance_reservation.to_dict(include=ir_keys))

        return d


class Event(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """An events occurring with the lease."""

    __tablename__ = 'events'

    id = _id_column()
    lease_id = sa.Column(sa.String(36), sa.ForeignKey('leases.id'))
    event_type = sa.Column(sa.String(66))
    time = sa.Column(sa.DateTime)
    status = sa.Column(sa.String(13))

    def to_dict(self):
        return super(Event, self).to_dict()


class ComputeHostReservation(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """Description

    Specifies resources asked by reservation from
    Compute Host Reservation API.
    """

    __tablename__ = 'computehost_reservations'

    id = _id_column()
    reservation_id = sa.Column(sa.String(36), sa.ForeignKey('reservations.id'))
    aggregate_id = sa.Column(sa.Integer)
    resource_properties = sa.Column(MediumText())
    count_range = sa.Column(sa.String(36))
    hypervisor_properties = sa.Column(MediumText())
    before_end = sa.Column(sa.String(36))

    def to_dict(self):
        return super(ComputeHostReservation, self).to_dict()


class InstanceReservations(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """The definition of a flavor of the reservation."""

    __tablename__ = 'instance_reservations'

    id = _id_column()
    reservation_id = sa.Column(sa.String(36), sa.ForeignKey('reservations.id'))
    vcpus = sa.Column(sa.Integer, nullable=False)
    memory_mb = sa.Column(sa.Integer, nullable=False)
    disk_gb = sa.Column(sa.Integer, nullable=False)
    amount = sa.Column(sa.Integer, nullable=False)
    affinity = sa.Column(sa.Boolean, nullable=False)
    resource_properties = sa.Column(MediumText(), nullable=True)
    flavor_id = sa.Column(sa.String(36), nullable=True)
    aggregate_id = sa.Column(sa.Integer, nullable=True)
    server_group_id = sa.Column(sa.String(36), nullable=True)


class ComputeHostAllocation(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """Mapping between ComputeHost, ComputeHostReservation and Reservation."""

    __tablename__ = 'computehost_allocations'

    id = _id_column()
    compute_host_id = sa.Column(sa.String(36))
    reservation_id = sa.Column(sa.String(36),
                               sa.ForeignKey('reservations.id'))

    def to_dict(self):
        return super(ComputeHostAllocation, self).to_dict()


class ComputeHost(mb.BlazarBase):
    """Description

    Specifies resources asked by reservation from
    Compute Host Reservation API.
    """

    __tablename__ = 'computehosts'

    id = _id_column()
    vcpus = sa.Column(sa.Integer, nullable=False)
    cpu_info = sa.Column(MediumText(), nullable=False)
    hypervisor_type = sa.Column(MediumText(), nullable=False)
    hypervisor_version = sa.Column(sa.Integer, nullable=False)
    hypervisor_hostname = sa.Column(sa.String(255), nullable=True)
    service_name = sa.Column(sa.String(255), nullable=True)
    memory_mb = sa.Column(sa.Integer, nullable=False)
    local_gb = sa.Column(sa.Integer, nullable=False)
    status = sa.Column(sa.String(13))
    availability_zone = sa.Column(sa.String(255), nullable=False)
    trust_id = sa.Column(sa.String(36), nullable=False)
    reservable = sa.Column(sa.Boolean, nullable=False,
                           server_default=sa.true())
    computehost_extra_capabilities = relationship('ComputeHostExtraCapability',
                                                  cascade="all,delete",
                                                  backref='computehost',
                                                  lazy='joined')

    def to_dict(self):
        return super(ComputeHost, self).to_dict()


class ComputeHostExtraCapability(mb.BlazarBase):
    """Description

    Allows to define extra capabilities per administrator request for each
    Compute Host added.
    """

    __tablename__ = 'computehost_extra_capabilities'

    id = _id_column()
    computehost_id = sa.Column(sa.String(36), sa.ForeignKey('computehosts.id'))
    capability_name = sa.Column(sa.String(64), nullable=False)
    capability_value = sa.Column(MediumText(), nullable=False)

    def to_dict(self):
        return super(ComputeHostExtraCapability, self).to_dict()


class NetworkSegment(mb.BlazarBase):
    """Description

    Specifies resources asked by reservation from Network Reservation API.
    """

    __tablename__ = 'network_segments'

    __table_args__ = (
        sa.UniqueConstraint('network_type', 'physical_network', 'segment_id'),
    )

    id = _id_column()
    # The physical mechanism by which the virtual network is implemented. For example: flat, geneve, gre, local, vlan, vxlan.
    network_type = sa.Column(sa.String(255), nullable=False)
    # Name of the physical network over which the virtual network is implemented
    physical_network = sa.Column(sa.String(255), nullable=True)
    # VLAN ID for VLAN networks or Tunnel ID for GENEVE/GRE/VXLAN networks
    segment_id = sa.Column(sa.Integer, nullable=False)

    def to_dict(self):
        return super(NetworkSegment, self).to_dict()


class NetworkReservation(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """Description

    Specifies resources asked by reservation from
    Network Reservation API.
    """

    __tablename__ = 'network_reservations'

    id = _id_column()
    reservation_id = sa.Column(sa.String(36), sa.ForeignKey('reservations.id'))
    resource_properties = sa.Column(MediumText())
    hypervisor_properties = sa.Column(MediumText())
    before_end = sa.Column(sa.String(36))
    network_name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(255))

    def to_dict(self):
        return super(NetworkReservation, self).to_dict()


class NetworkAllocation(mb.BlazarBase, mb.SoftDeleteMixinWithUuid):
    """Mapping between NetworkSegment, NetworkReservation and Reservation."""

    __tablename__ = 'network_allocations'

    id = _id_column()
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('network_segments.id'))
    reservation_id = sa.Column(sa.String(36),
                               sa.ForeignKey('reservations.id'))

    def to_dict(self):
        return super(NetworkAllocation, self).to_dict()
