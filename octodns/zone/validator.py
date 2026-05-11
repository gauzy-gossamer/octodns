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
        msg = self.reason
        contexts = {
            r.context for r in self.records if getattr(r, 'context', None)
        }
        if contexts:
            msg += f" ({', '.join(sorted(contexts))})"
        return msg

    def __repr__(self):
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


class MailZoneValidator(ZoneValidator):
    '''
    Comprehensive best-practice validator for mail records (MX, SPF, DMARC).

    Can operate in two modes: 'mail' and 'no-mail'. In 'auto' mode (default), it
    detects the mode based on the presence of mail-related records (MX anywhere
    in the zone, SPF at the apex, or DMARC at _dmarc). If no mail-related
    records are found, it is a no-op. If any are found, it detects the mode
    based on the presence of non-null MX records at the apex.

    'mail' mode enforces:
    - Multiple MX records for redundancy (at apex and throughout the zone).
    - Presence of an SPF record at the apex.
    - SPF record terminates with ~all or -all.
    - Presence of a DMARC record at _dmarc.

    'no-mail' mode enforces:
    - Presence of a single Null MX record (0 .) at the apex.
    - SPF record at the apex is exactly 'v=spf1 -all'.
    - DMARC record at _dmarc has p=reject.
    '''

    def __init__(self, id, mode='auto', sets=None):
        super().__init__(id, sets=sets)
        self.log = getLogger('MailZoneValidator[{id}]')
        if mode not in ('auto', 'mail', 'no-mail'):
            raise ValueError(f'Unknown mode "{mode}"')
        self.mode = mode

    def _validate_mail(
        self,
        zone,
        apex_mx_record,
        other_mx_records,
        apex_txt,
        apex_spf_value,
        dmarc_txt,
        dmarc_value,
    ):
        reasons = []

        # MX redundancy (Apex and elsewhere)
        for record in (
            [apex_mx_record] if apex_mx_record else []
        ) + other_mx_records:
            if len(record.values) < 2:
                reasons.append(
                    ValidationReason(
                        f'MX record "{record.fqdn}" should have at least 2 values for redundancy, found {len(record.values)}',
                        [record],
                    )
                )

        # Check for presence at apex
        if not apex_mx_record:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" handles mail but is missing MX records at the apex',
                    [],
                )
            )

        # SPF
        if not apex_spf_value:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" handles mail but is missing an SPF TXT record at the apex',
                    {apex_txt} if apex_txt else [],
                )
            )
        elif not (
            apex_spf_value.endswith(' -all') or apex_spf_value.endswith(' ~all')
        ):
            reasons.append(
                ValidationReason(
                    f'SPF record at the apex of "{zone.decoded_name}" should terminate with "~all" or "-all"',
                    {apex_txt},
                )
            )

        # DMARC
        if not dmarc_value:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" handles mail but is missing a DMARC TXT record at _dmarc',
                    {dmarc_txt} if dmarc_txt else [],
                )
            )
        elif 'p=' not in dmarc_value:
            reasons.append(
                ValidationReason(
                    f'DMARC record at _dmarc.{zone.decoded_name} is missing a policy (p=...)',
                    [dmarc_txt],
                )
            )

        return reasons

    def _validate_no_mail(
        self,
        zone,
        apex_mx_record,
        apex_txt,
        apex_spf_value,
        dmarc_txt,
        dmarc_value,
    ):
        reasons = []

        # MX
        if not apex_mx_record:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail but is missing a Null MX record (0 .)',
                    [],
                )
            )
        elif (
            len(apex_mx_record.values) != 1
            or apex_mx_record.values[0].preference != 0
            or str(apex_mx_record.values[0].exchange) != '.'
        ):
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail and should have a single Null MX record (0 .)',
                    [apex_mx_record],
                )
            )

        # SPF
        if apex_spf_value is None:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail but is missing strict SPF TXT record "v=spf1 -all"',
                    [],
                )
            )
        elif not apex_spf_value == 'v=spf1 -all':
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail and should have a single strict SPF TXT record "v=spf1 -all"',
                    [apex_txt],
                )
            )

        # DMARC
        if dmarc_value is None:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail but is missing strict DMARC TXT record "v=DMARC1; p=reject;"',
                    [],
                )
            )
        elif 'p=reject' not in dmarc_value:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail and should have a DMARC TXT record with "v=DMARC1; p=reject;"',
                    [dmarc_txt],
                )
            )

        return reasons

    def validate(self, zone):
        mode = self.mode

        apex_mx_record = zone.get_type('', 'MX')

        other_mx_records = [
            r for r in zone.records if r.name != '' and r._type == 'MX'
        ]

        apex_txt = zone.get_type('', 'TXT')
        apex_spf_value = (
            [
                v
                for v in [i.lower().replace('\\', '') for i in apex_txt.values]
                if v.startswith('v=spf1')
            ]
            # there can only be 0/1
            if apex_txt
            else None
        )
        if apex_spf_value:
            if len(apex_spf_value) > 1:
                return [
                    ValidationReason(
                        reason=f'zone "{zone.decoded_name}" has multiple SPF values',
                        records={apex_txt},
                    )
                ]
            apex_spf_value = apex_spf_value[0]

        dmarc_txt = zone.get_type('_dmarc', 'TXT')
        dmarc_value = (
            [
                v
                for v in [v.lower().replace('\\', '') for v in dmarc_txt.values]
                if v.startswith('v=dmarc1')
            ]
            # there can only be 0/1
            if dmarc_txt
            else None
        )
        if dmarc_value:
            if len(dmarc_value) > 1:
                return [
                    ValidationReason(
                        reason=f'zone "{zone.decoded_name}" has multiple DMARC values',
                        records={dmarc_txt},
                    )
                ]
            dmarc_value = dmarc_value[0]

        if mode == 'auto':
            if (
                apex_mx_record
                or other_mx_records
                or apex_spf_value
                or dmarc_value
            ):
                self.log.debug(
                    'validate: zone=%s, has mail related records/values, apex_mx_record=%s, other_mx_records=%s, apex_spf_value=%s, dmarc_value=%s',
                    zone.decoded_name,
                    apex_mx_record,
                    other_mx_records,
                    apex_spf_value,
                    dmarc_value,
                )
                if apex_spf_value and apex_spf_value == 'v=spf1 -all':
                    self.log.debug(
                        'validate: zone=%s, apex_spf_value indicates no-mail'
                    )
                    mode = 'no-mail'
                elif dmarc_value and dmarc_value == 'v=dmarc1; p=reject;':
                    self.log.debug(
                        'validate: zone=%s, dmarc_value indicates no-mail'
                    )
                    mode = 'no-mail'
                elif (
                    apex_mx_record
                    and len(apex_mx_record.values) == 1
                    and apex_mx_record.values[0].preference == 0
                    and apex_mx_record.values[0].exchange == '.'
                ):
                    self.log.debug(
                        'validate: zone=%s, apex_mx_record indicates'
                    )
                    mode = 'no-mail'
                else:
                    self.log.debug('validate: zone=%s, assuming mail handling')
                    mode = 'mail'
            else:
                self.log.debug('validate: zone=%s, no signs of mail handling')
                return []

        if mode == 'mail':
            return self._validate_mail(
                zone,
                apex_mx_record=apex_mx_record,
                other_mx_records=other_mx_records,
                apex_txt=apex_txt,
                apex_spf_value=apex_spf_value,
                dmarc_txt=dmarc_txt,
                dmarc_value=dmarc_value,
            )

        return self._validate_no_mail(
            zone,
            apex_mx_record=apex_mx_record,
            apex_txt=apex_txt,
            apex_spf_value=apex_spf_value,
            dmarc_txt=dmarc_txt,
            dmarc_value=dmarc_value,
        )


zone_validators = ZoneValidatorRegistry()
zone_validators.register(MailZoneValidator('mail', sets={'best-practice'}))
