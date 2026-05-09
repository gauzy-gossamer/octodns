#
#
#

from unittest import TestCase

from helpers import TestZoneValidator as _TestZoneValidator
from helpers import zone_validators_snapshot

from octodns.record import Record
from octodns.zone import Zone
from octodns.zone.exception import ValidationError, ZoneException
from octodns.zone.validator import (
    ApexSpfPresenceZoneValidator,
    MultiValueMxZoneValidator,
    ValidationReason,
    ZoneValidator,
    ZoneValidatorRegistry,
)


def _make_zone(name='unit.tests.'):
    return Zone(name, [])


def _add_record(zone, name, data):
    return Record.new(zone, name, data, lenient=True)


class TestZoneValidatorBase(TestCase):
    def test_zone_validator_base(self):
        v = ZoneValidator('test')
        zone = _make_zone()
        self.assertEqual([], v.validate(zone))

    def test_validator_requires_id(self):
        with self.assertRaises(ValueError):
            ZoneValidator('')
        with self.assertRaises(ValueError):
            ZoneValidator(None)
        with self.assertRaises(TypeError):
            ZoneValidator()
        self.assertEqual('custom', ZoneValidator('custom').id)

    def test_validator_sets_attribute(self):
        v = ZoneValidator('test-default')
        self.assertIsNone(v.sets)

        v2 = ZoneValidator('test-custom', sets=('rfc', 'best-practice'))
        self.assertEqual({'rfc', 'best-practice'}, v2.sets)

        v3 = ZoneValidator('test-empty', sets=())
        self.assertEqual(set(), v3.sets)


class TestValidationError(TestCase):
    def test_build_message_single_reason(self):
        msg = ValidationError.build_message('unit.tests.', ['some reason'])
        self.assertIn('unit.tests', msg)
        self.assertIn('some reason', msg)

    def test_build_message_multiple_reasons(self):
        msg = ValidationError.build_message(
            'unit.tests.', ['reason one', 'reason two']
        )
        self.assertIn('reason one', msg)
        self.assertIn('reason two', msg)

    def test_build_message_with_context(self):
        msg = ValidationError.build_message(
            'unit.tests.', ['some reason'], context='some context'
        )
        self.assertIn('some context', msg)

    def test_exception_attributes(self):
        exc = ValidationError('unit.tests.', ['r1', 'r2'], context='ctx')
        self.assertEqual('unit.tests.', exc.zone_name)
        self.assertEqual(['r1', 'r2'], exc.reasons)
        self.assertEqual('ctx', exc.context)

    def test_exception_message(self):
        exc = ValidationError('unit.tests.', ['bad thing'])
        self.assertIn('unit.tests', str(exc))
        self.assertIn('bad thing', str(exc))


class TestZoneValidatorRegistry(TestCase):
    def test_register_valid(self):
        with zone_validators_snapshot():
            v = ZoneValidator('test-reg')
            Zone.validators.register(v)
            self.assertIn('test-reg', Zone.validators.available)

    def test_register_wrong_type(self):
        with zone_validators_snapshot():

            class NotAV:
                id = 'bad'

            with self.assertRaises(ZoneException) as ctx:
                Zone.validators.register(NotAV())
            self.assertIn('must be a ZoneValidator', str(ctx.exception))

    def test_register_duplicate_id(self):
        with zone_validators_snapshot():
            v = ZoneValidator('test-dup')
            Zone.validators.register(v)
            with self.assertRaises(ZoneException) as ctx:
                Zone.validators.register(ZoneValidator('test-dup'))
            self.assertIn('already registered', str(ctx.exception))

    def test_enable_sets(self):
        with zone_validators_snapshot():
            v_always = ZoneValidator('always-active')
            v_legacy = ZoneValidator('legacy-only', sets={'legacy'})
            v_best = ZoneValidator('best-practice-only', sets={'best-practice'})
            reg = ZoneValidatorRegistry()
            reg.register(v_always)
            reg.register(v_legacy)
            reg.register(v_best)

            reg.enable_sets({'legacy'})
            self.assertTrue(reg.configured)
            self.assertIn('always-active', reg.active)
            self.assertIn('legacy-only', reg.active)
            self.assertNotIn('best-practice-only', reg.active)

            reg.enable_sets({'best-practice'})
            self.assertIn('always-active', reg.active)
            self.assertNotIn('legacy-only', reg.active)
            self.assertIn('best-practice-only', reg.active)

    def test_enable_explicit(self):
        with zone_validators_snapshot():
            v = ZoneValidator('explicit', sets={'custom'})
            Zone.validators.register(v)
            Zone.validators.enable_sets({'legacy'})
            self.assertNotIn('explicit', Zone.validators.active)
            Zone.validators.enable('explicit')
            self.assertIn('explicit', Zone.validators.active)

    def test_enable_unknown(self):
        with zone_validators_snapshot():
            with self.assertRaises(ZoneException) as ctx:
                Zone.validators.enable('no-such-validator')
            self.assertIn('Unknown zone validator', str(ctx.exception))

    def test_disable(self):
        with zone_validators_snapshot():
            v = ZoneValidator('to-disable')
            Zone.validators.register(v)
            Zone.validators.enable_sets(set())
            Zone.validators.enable('to-disable')
            self.assertIn('to-disable', Zone.validators.active)
            removed = Zone.validators.disable('to-disable')
            self.assertTrue(removed)
            self.assertNotIn('to-disable', Zone.validators.active)

    def test_disable_not_active(self):
        with zone_validators_snapshot():
            Zone.validators.enable_sets({'legacy'})
            removed = Zone.validators.disable('multi-value-mx')
            self.assertFalse(removed)

    def test_disable_bridge_rejected(self):
        with zone_validators_snapshot():
            with self.assertRaises(ZoneException) as ctx:
                Zone.validators.disable('_internal')
            self.assertIn('Cannot disable bridge', str(ctx.exception))

    def test_reset_active(self):
        with zone_validators_snapshot():
            Zone.validators.enable_sets({'legacy'})
            Zone.validators.reset_active()
            self.assertEqual({}, Zone.validators.active)

    def test_registered_returns_active_list(self):
        with zone_validators_snapshot():
            v = ZoneValidator('reg-test')
            Zone.validators.register(v)
            Zone.validators.enable_sets(set())
            Zone.validators.enable('reg-test')
            self.assertIn(v, Zone.validators.registered())

    def test_available_validators(self):
        with zone_validators_snapshot():
            avail = Zone.validators.available_validators()
            ids = [v.id for v in avail]
            self.assertIn('multi-value-mx', ids)
            self.assertIn('apex-spf-presence', ids)

    def test_process_zone_lazy_init(self):
        with zone_validators_snapshot():
            reg = ZoneValidatorRegistry()
            zone = _make_zone()
            with self.assertLogs('Zone', level='WARNING') as logs:
                reg.process_zone(zone)
            self.assertTrue(reg.configured)
            self.assertTrue(
                any(
                    'automatically enabling legacy set' in m
                    for m in logs.output
                )
            )

    def test_process_zone_collects_reasons(self):
        with zone_validators_snapshot():
            zone = _make_zone()
            records = [
                _add_record(
                    zone, 'a', {'ttl': 30, 'type': 'A', 'value': '1.2.3.4'}
                )
            ]
            reasons_returned = [ValidationReason('reason one', records)]

            class FailingValidator(ZoneValidator):
                def validate(self, zone):
                    return reasons_returned

            reg = ZoneValidatorRegistry()
            reg.register(FailingValidator('failing'))
            reg.enable_sets(set())
            reg.enable('failing')
            result = reg.process_zone(zone)
            self.assertEqual(reasons_returned, result)
            self.assertEqual('reason one', str(result[0]))
            self.assertEqual(set(records), result[0].records)
            self.assertFalse(result[0].lenient)

    def test_process_zone_collects_reasons_lenient(self):
        with zone_validators_snapshot():
            zone = _make_zone()
            records = [
                _add_record(
                    zone,
                    'a',
                    {
                        'ttl': 30,
                        'type': 'A',
                        'value': '1.2.3.4',
                        'octodns': {'lenient': True},
                    },
                )
            ]
            reasons_returned = [ValidationReason('reason one', records)]

            class FailingValidator(ZoneValidator):
                def validate(self, zone):
                    return reasons_returned

            Zone.register_zone_validator(FailingValidator('failing'))
            Zone.enable_zone_validators(set())
            Zone.enable_zone_validator('failing')
            with self.assertLogs('Zone', level='WARNING') as logs:
                zone.validate()
            self.assertTrue(any('reason one' in m for m in logs.output))

    def test_process_zone_no_active_no_reasons(self):
        with zone_validators_snapshot():
            reg = ZoneValidatorRegistry()
            reg.enable_sets(set())
            zone = _make_zone()
            result = reg.process_zone(zone)
            self.assertEqual([], result)


class TestZoneClassmethods(TestCase):
    def test_register_zone_validator(self):
        with zone_validators_snapshot():
            v = ZoneValidator('cm-test')
            Zone.register_zone_validator(v)
            self.assertIn('cm-test', Zone.validators.available)

    def test_enable_zone_validators(self):
        with zone_validators_snapshot():
            Zone.enable_zone_validators({'legacy'})
            self.assertTrue(Zone.validators.configured)

    def test_enable_zone_validator(self):
        with zone_validators_snapshot():
            v = ZoneValidator('cm-enable', sets={'custom'})
            Zone.register_zone_validator(v)
            Zone.enable_zone_validators(set())
            Zone.enable_zone_validator('cm-enable')
            self.assertIn('cm-enable', Zone.validators.active)

    def test_disable_zone_validator(self):
        with zone_validators_snapshot():
            v = ZoneValidator('cm-disable')
            Zone.register_zone_validator(v)
            Zone.enable_zone_validators(set())
            Zone.enable_zone_validator('cm-disable')
            removed = Zone.disable_zone_validator('cm-disable')
            self.assertTrue(removed)
            self.assertNotIn('cm-disable', Zone.validators.active)

    def test_registered_zone_validators(self):
        with zone_validators_snapshot():
            Zone.enable_zone_validators(set())
            self.assertEqual([], Zone.registered_zone_validators())

    def test_available_zone_validators(self):
        with zone_validators_snapshot():
            avail = Zone.available_zone_validators()
            self.assertIsInstance(avail, list)
            ids = [v.id for v in avail]
            self.assertIn('multi-value-mx', ids)


class TestZoneValidateMethod(TestCase):
    def test_validate_passes_clean_zone(self):
        with zone_validators_snapshot():
            Zone.enable_zone_validators(set())
            zone = _make_zone()
            zone.validate()

    def test_validate_raises_on_failure(self):
        with zone_validators_snapshot():

            class FailValidator(ZoneValidator):
                def validate(self, zone):
                    return [ValidationReason('zone has a problem', [])]

            reg_v = FailValidator('fail-test')
            Zone.register_zone_validator(reg_v)
            Zone.enable_zone_validators(set())
            Zone.enable_zone_validator('fail-test')
            zone = _make_zone()
            with self.assertRaises(ValidationError) as ctx:
                zone.validate()
            self.assertIn('zone has a problem', str(ctx.exception))

    def test_validate_lenient_warns_not_raises(self):
        with zone_validators_snapshot():

            class FailValidator(ZoneValidator):
                def validate(self, zone):
                    return [ValidationReason('zone has a problem', [])]

            reg_v = FailValidator('fail-lenient')
            Zone.register_zone_validator(reg_v)
            Zone.enable_zone_validators(set())
            Zone.enable_zone_validator('fail-lenient')
            zone = _make_zone()
            with self.assertLogs('Zone', level='WARNING') as logs:
                zone.validate(lenient=True)
            self.assertTrue(any('zone has a problem' in m for m in logs.output))


class TestBuiltinZoneValidators(TestCase):
    def test_multi_value_mx_passes_two_values(self):
        zone = _make_zone()
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [
                    {'preference': 10, 'exchange': 'mail1.unit.tests.'},
                    {'preference': 20, 'exchange': 'mail2.unit.tests.'},
                ],
            },
        )
        zone.add_record(mx, replace=True)
        v = MultiValueMxZoneValidator('test')
        self.assertEqual([], v.validate(zone))

    def test_multi_value_mx_fails_single_value(self):
        zone = _make_zone()
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 10, 'exchange': 'mail1.unit.tests.'}],
            },
        )
        zone.add_record(mx, replace=True)
        v = MultiValueMxZoneValidator('test')
        reasons = v.validate(zone)
        self.assertEqual(1, len(reasons))
        self.assertIn('at least 2 values', str(reasons[0]))
        self.assertIn('unit.tests.', str(reasons[0]))

    def test_multi_value_mx_no_mx_records(self):
        zone = _make_zone()
        v = MultiValueMxZoneValidator('test')
        self.assertEqual([], v.validate(zone))

    def test_multi_value_mx_non_apex_mx(self):
        zone = _make_zone()
        mx = _add_record(
            zone,
            'sub',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 10, 'exchange': 'mail1.unit.tests.'}],
            },
        )
        zone.add_record(mx)
        v = MultiValueMxZoneValidator('test')
        reasons = v.validate(zone)
        self.assertEqual(1, len(reasons))
        self.assertIn('sub.unit.tests.', str(reasons[0]))

    def test_apex_spf_presence_passes(self):
        zone = _make_zone()
        txt = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': ['v=spf1 include:example.com ~all', 'some-other-txt'],
            },
        )
        zone.add_record(txt, replace=True)
        v = ApexSpfPresenceZoneValidator('test')
        self.assertEqual([], v.validate(zone))

    def test_apex_spf_presence_fails_no_txt(self):
        zone = _make_zone()
        v = ApexSpfPresenceZoneValidator('test')
        reasons = v.validate(zone)
        self.assertEqual(1, len(reasons))
        self.assertIn('no TXT records', str(reasons[0]))

    def test_apex_spf_presence_fails_no_spf_value(self):
        zone = _make_zone()
        txt = _add_record(
            zone,
            '',
            {'ttl': 300, 'type': 'TXT', 'values': ['google-site-verify=abc']},
        )
        zone.add_record(txt, replace=True)
        v = ApexSpfPresenceZoneValidator('test')
        reasons = v.validate(zone)
        self.assertEqual(1, len(reasons))
        self.assertIn('v=spf1', str(reasons[0]))

    def test_builtin_ids(self):
        ids = [v.id for v in Zone.validators.available_validators()]
        self.assertIn('multi-value-mx', ids)
        self.assertIn('apex-spf-presence', ids)

    def test_builtins_in_best_practice_set(self):
        with zone_validators_snapshot():
            Zone.enable_zone_validators({'best-practice'})
            active_ids = [v.id for v in Zone.validators.registered()]
            self.assertIn('multi-value-mx', active_ids)
            self.assertIn('apex-spf-presence', active_ids)

    def test_builtins_not_in_legacy_set(self):
        with zone_validators_snapshot():
            Zone.enable_zone_validators({'legacy'})
            active_ids = [v.id for v in Zone.validators.registered()]
            self.assertNotIn('multi-value-mx', active_ids)
            self.assertNotIn('apex-spf-presence', active_ids)

    def test_test_zone_validator_helper(self):
        with zone_validators_snapshot():
            v = _TestZoneValidator('helper-test', require_mx=True)
            zone = _make_zone()
            reasons = v.validate(zone)
            self.assertEqual(1, len(reasons))
            self.assertIn('MX record', str(reasons[0]))

            mx = _add_record(
                zone,
                '',
                {
                    'ttl': 300,
                    'type': 'MX',
                    'values': [
                        {'preference': 10, 'exchange': 'mail1.unit.tests.'}
                    ],
                },
            )
            zone.add_record(mx, replace=True)
            self.assertEqual([], v.validate(zone))
