#
#
#

from logging import getLogger

from .exception import ZoneException


class ZoneValidatorRegistry:
    log = getLogger('Zone')

    def __init__(self):
        self.available = {}
        self.active = {}
        self.configured = False

    def register(self, validator):
        if not isinstance(validator, ZoneValidator):
            raise ZoneException(
                f'{validator.__class__.__name__} must be a ZoneValidator instance'
            )
        if validator.id in self.available:
            raise ZoneException(
                f'ZoneValidator id "{validator.id}" already registered'
            )
        self.available[validator.id] = validator

    def enable_sets(self, sets):
        self.configured = True
        self.active.clear()
        sets = set(sets)
        for validator in self.available.values():
            if validator.sets is None or sets & validator.sets:
                self.active[validator.id] = validator

    def enable(self, id):
        if id not in self.available:
            raise ZoneException(f'Unknown zone validator id "{id}"')
        self.active[id] = self.available[id]

    def disable(self, validator_id):
        if validator_id.startswith('_'):
            raise ZoneException(
                f'Cannot disable bridge zone validator "{validator_id}"'
            )
        return self.active.pop(validator_id, None) is not None

    def reset_active(self):
        self.active.clear()

    def registered(self):
        return list(self.active.values())

    def available_validators(self):
        return list(self.available.values())

    def process_zone(self, zone):
        if not self.configured:
            self.log.warning(
                'process_zone: no zone validators configured, automatically enabling legacy set'
            )
            self.enable_sets({'legacy'})

        reasons = []
        for validator in self.active.values():
            reasons.extend(validator.validate(zone))

        return reasons


class ValidationReason:
    def __init__(self, reason, records):
        self.reason = reason
        self.records = set(records)

    @property
    def lenient(self):
        return bool(self.records) and all(r.lenient for r in self.records)

    def __str__(self):
        return self.reason


class ZoneValidator:
    '''
    Base class for zone-level validators.

    Subclasses override ``validate`` to return a list of ValidationReason
    objects describing any validation failures. An empty list indicates the
    zone is valid. The zone validator receives the fully assembled desired
    Zone and may examine any records within it. Because zone validators see
    the whole zone at once, they are suited for cross-record checks (e.g.
    requiring at least two MX values at the apex) that per-record validators
    cannot perform.

    Every zone validator instance has a non-empty ``id`` — a short, stable,
    kebab-case identifier (e.g. ``'multi-value-mx'``). Config-registered
    validators receive their config key as ``id`` automatically.
    '''

    def __init__(self, id, sets=None):
        '''
        :param id: Non-empty identifier for this validator instance.
        :param sets: Iterable of set names, or ``None`` to always activate.
        '''
        if not id:
            raise ValueError(
                f'{self.__class__.__name__} requires a non-empty id'
            )
        self.id = id
        self.sets = set(sets) if sets is not None else None

    def validate(self, zone):
        '''
        Validate a fully populated zone.

        :param zone: The Zone to validate.
        :returns: list[ValidationReason] of reason objects; empty when valid.
        '''
        return []


class MultiValueMxZoneValidator(ZoneValidator):
    '''
    Checks that every MX record in the zone has at least two values.
    Single-value MX records are technically valid but are not recommended
    in production zones as they create a single point of failure.
    '''

    def validate(self, zone):
        reasons = []
        for record in zone.records:
            if record._type == 'MX' and len(record.values) < 2:
                reasons.append(
                    ValidationReason(
                        f'MX record "{record.fqdn}" should have at least 2 values'
                        f' for redundancy, found {len(record.values)}',
                        [record],
                    )
                )
        return reasons


class ApexSpfPresenceZoneValidator(ZoneValidator):
    '''
    Checks that the zone apex has at least one TXT record whose value begins
    with ``v=spf1``, indicating an SPF policy is published. Publishing SPF
    records helps prevent email spoofing of the domain.
    '''

    def validate(self, zone):
        apex_txts = zone.get('', type='TXT')
        if not apex_txts:
            return [
                ValidationReason(
                    f'zone "{zone.decoded_name}" has no TXT records at the apex;'
                    ' add an SPF record (v=spf1 ...)',
                    [],
                )
            ]
        for record in apex_txts:
            for value in record.values:
                if str(value).startswith('v=spf1'):
                    return []
        return [
            ValidationReason(
                f'zone "{zone.decoded_name}" has no SPF TXT record at the apex'
                ' (no value starting with "v=spf1")',
                apex_txts,
            )
        ]


zone_validators = ZoneValidatorRegistry()
zone_validators.register(
    MultiValueMxZoneValidator('multi-value-mx', sets={'best-practice'})
)
zone_validators.register(
    ApexSpfPresenceZoneValidator('apex-spf-presence', sets={'best-practice'})
)
