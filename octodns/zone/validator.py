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
        if mode not in ('auto', 'mail', 'no-mail'):
            raise ValueError(f'Unknown mode "{mode}"')
        self.mode = mode

    def _validate_mail(self, zone):
        reasons = []

        # MX redundancy (Apex and elsewhere)
        for record in zone.records:
            if record._type == 'MX':
                if len(record.values) < 2:
                    reasons.append(
                        ValidationReason(
                            f'MX record "{record.fqdn}" should have at least 2'
                            f' values for redundancy, found'
                            f' {len(record.values)}',
                            [record],
                        )
                    )

        # Check for presence at apex
        apex_mxs = zone.get('', type='MX')
        if not apex_mxs:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" handles mail but is missing'
                    ' MX records at the apex',
                    [],
                )
            )

        # SPF
        apex_txts = zone.get('', type='TXT')
        spf_record = None
        if apex_txts:
            # We expect at most one TXT record at apex that contains all values
            apex_txt = next(iter(apex_txts))
            for value in apex_txt.values:
                # Internally everything is escaped
                val = str(value).replace('\\', '')
                if val.lower().startswith('v=spf1'):
                    if spf_record:
                        reasons.append(
                            ValidationReason(
                                f'zone "{zone.decoded_name}" has multiple'
                                ' SPF TXT values at the apex',
                                [apex_txt],
                            )
                        )
                    spf_record = val

        if not spf_record:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" handles mail but is missing'
                    ' an SPF TXT record at the apex',
                    list(apex_txts) if apex_txts else [],
                )
            )
        elif not (
            spf_record.lower().endswith(' -all')
            or spf_record.lower().endswith(' ~all')
        ):
            reasons.append(
                ValidationReason(
                    f'SPF record at the apex of "{zone.decoded_name}" should'
                    ' terminate with "~all" or "-all"',
                    list(apex_txts),
                )
            )

        # DMARC
        dmarc_txts = zone.get('_dmarc', type='TXT')
        dmarc_value = None
        if dmarc_txts:
            dmarc_txt = next(iter(dmarc_txts))
            for value in dmarc_txt.values:
                # Internally everything is escaped
                val = str(value).replace('\\', '')
                if val.lower().startswith('v=dmarc1;'):
                    dmarc_value = val
                    break

        if not dmarc_value:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" handles mail but is missing'
                    ' a DMARC TXT record at _dmarc',
                    list(dmarc_txts) if dmarc_txts else [],
                )
            )
        elif 'p=' not in dmarc_value.lower():
            dmarc_txt = next(iter(dmarc_txts))
            reasons.append(
                ValidationReason(
                    f'DMARC record at _dmarc.{zone.decoded_name} is missing'
                    ' a policy (p=...)',
                    [dmarc_txt],
                )
            )

        return reasons

    def _validate_no_mail(self, zone):
        reasons = []

        # MX
        apex_mxs = zone.get('', type='MX')
        if not apex_mxs:
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail but is'
                    ' missing a Null MX record (0 .)',
                    [],
                )
            )
        else:
            apex_mx = next(iter(apex_mxs))
            if (
                len(apex_mx.values) != 1
                or apex_mx.values[0].preference != 0
                or str(apex_mx.values[0].exchange) != '.'
            ):
                reasons.append(
                    ValidationReason(
                        f'zone "{zone.decoded_name}" does not handle mail and'
                        ' should have a single Null MX record (0 .)',
                        [apex_mx],
                    )
                )

        # SPF
        apex_txts = zone.get('', type='TXT')
        spf_value = None
        has_other_spf_values = False
        if apex_txts:
            apex_txt = next(iter(apex_txts))
            for value in apex_txt.values:
                # Internally everything is escaped
                val = str(value).replace('\\', '')
                if val.lower().startswith('v=spf1'):
                    if spf_value:
                        has_other_spf_values = True
                    spf_value = val
        if (
            spf_value is None
            or spf_value.lower() != 'v=spf1 -all'
            or has_other_spf_values
            or (apex_txts and len(next(iter(apex_txts)).values) != 1)
        ):
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail and'
                    ' should have a single strict SPF TXT record'
                    ' "v=spf1 -all"',
                    list(apex_txts) if apex_txts else [],
                )
            )

        # DMARC
        dmarc_txts = zone.get('_dmarc', type='TXT')
        dmarc_value = None
        has_other_dmarc_values = False
        if dmarc_txts:
            dmarc_txt = next(iter(dmarc_txts))
            for value in dmarc_txt.values:
                # Internally everything is escaped
                val = str(value).replace('\\', '')
                if val.lower().startswith('v=dmarc1;'):
                    if dmarc_value:
                        has_other_dmarc_values = True
                    dmarc_value = val
        if (
            not dmarc_value
            or 'p=reject' not in dmarc_value.lower()
            or has_other_dmarc_values
            or (dmarc_txts and len(next(iter(dmarc_txts)).values) != 1)
        ):
            reasons.append(
                ValidationReason(
                    f'zone "{zone.decoded_name}" does not handle mail and'
                    ' should have a DMARC TXT record with "v=DMARC1; p=reject;"',
                    list(dmarc_txts) if dmarc_txts else [],
                )
            )

        return reasons

    def validate(self, zone):
        mode = self.mode
        if mode == 'auto':
            # Check for signs of mail configuration
            has_mx = any(r._type == 'MX' for r in zone.records)

            spf_sign = False
            apex_txts = zone.get('', type='TXT')
            if apex_txts:
                apex_txt = next(iter(apex_txts))
                for value in apex_txt.values:
                    if (
                        str(value)
                        .replace('\\', '')
                        .lower()
                        .startswith('v=spf1')
                    ):
                        spf_sign = True
                        break

            dmarc_sign = False
            dmarc_txts = zone.get('_dmarc', type='TXT')
            if dmarc_txts:
                dmarc_txt = next(iter(dmarc_txts))
                for value in dmarc_txt.values:
                    if (
                        str(value)
                        .replace('\\', '')
                        .lower()
                        .startswith('v=dmarc1')
                    ):
                        dmarc_sign = True
                        break

            if not (has_mx or spf_sign or dmarc_sign):
                # No signs of mail, so we're done
                return []

            apex_mxs = zone.get('', type='MX')
            if apex_mxs:
                apex_mx = next(iter(apex_mxs))
                if not (
                    len(apex_mx.values) == 1
                    and apex_mx.values[0].preference == 0
                    and str(apex_mx.values[0].exchange) == '.'
                ):
                    mode = 'mail'
                else:
                    mode = 'no-mail'
            else:
                mode = 'no-mail'

        if mode == 'mail':
            return self._validate_mail(zone)
        else:
            return self._validate_no_mail(zone)


zone_validators = ZoneValidatorRegistry()
zone_validators.register(MailZoneValidator('mail', sets={'best-practice'}))
