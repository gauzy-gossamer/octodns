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
    MailZoneValidator,
    ValidationReason,
    ZoneValidator,
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
            self.assertEqual(
                'NotAV must be a ZoneValidator instance', str(ctx.exception)
            )

    def test_register_duplicate_id(self):
        with zone_validators_snapshot():
            v1 = ZoneValidator('dup')
            v2 = ZoneValidator('dup')
            Zone.validators.register(v1)
            with self.assertRaises(ZoneException) as ctx:
                Zone.validators.register(v2)
            self.assertEqual(
                'ZoneValidator id "dup" already registered', str(ctx.exception)
            )

    def test_enable_sets(self):
        with zone_validators_snapshot():
            Zone.validators.register(ZoneValidator('v1', sets=['s1']))
            Zone.validators.register(ZoneValidator('v2', sets=['s2']))
            Zone.validators.register(ZoneValidator('v3', sets=['s1', 's2']))
            Zone.validators.register(ZoneValidator('v4'))

            Zone.validators.enable_sets(['s1'])
            active = Zone.validators.active
            self.assertIn('v1', active)
            self.assertNotIn('v2', active)
            self.assertIn('v3', active)
            self.assertIn('v4', active)

            Zone.validators.enable_sets(['s2'])
            active = Zone.validators.active
            self.assertNotIn('v1', active)
            self.assertIn('v2', active)
            self.assertIn('v3', active)
            self.assertIn('v4', active)

    def test_enable_by_id(self):
        with zone_validators_snapshot():
            v = ZoneValidator('manual')
            Zone.validators.register(v)
            self.assertNotIn('manual', Zone.validators.active)
            Zone.validators.enable('manual')
            self.assertIn('manual', Zone.validators.active)

            with self.assertRaises(ZoneException) as ctx:
                Zone.validators.enable('unknown')
            self.assertEqual(
                'Unknown zone validator id "unknown"', str(ctx.exception)
            )

    def test_disable_by_id(self):
        with zone_validators_snapshot():
            v = ZoneValidator('to-disable')
            Zone.validators.register(v)
            Zone.validators.enable('to-disable')
            self.assertTrue(Zone.validators.disable('to-disable'))
            self.assertNotIn('to-disable', Zone.validators.active)
            self.assertFalse(Zone.validators.disable('unknown'))

    def test_disable_bridge_fails(self):
        with zone_validators_snapshot():
            Zone.validators.active['_bridge'] = ZoneValidator('_bridge')
            with self.assertRaises(ZoneException) as ctx:
                Zone.validators.disable('_bridge')
            self.assertIn('Cannot disable bridge', str(ctx.exception))

    def test_reset_active(self):
        with zone_validators_snapshot():
            Zone.validators.active['v'] = ZoneValidator('v')
            Zone.validators.reset_active()
            self.assertEqual({}, Zone.validators.active)

    def test_registered_and_available(self):
        with zone_validators_snapshot():
            v = ZoneValidator('reg-test')
            Zone.validators.register(v)
            Zone.validators.enable('reg-test')
            self.assertIn(v, Zone.validators.registered())
            self.assertIn(v, Zone.validators.available_validators())

    def test_process_zone(self):
        with zone_validators_snapshot():
            # Test auto-enabling legacy set
            Zone.validators.configured = False
            zone = _make_zone()
            self.assertEqual([], Zone.validators.process_zone(zone))
            self.assertTrue(Zone.validators.configured)

            # Test processing with active validators
            Zone.validators.active['test'] = ZoneValidator('test')
            self.assertEqual([], Zone.validators.process_zone(zone))


class TestValidationReason(TestCase):
    def test_validation_reason(self):
        r = ValidationReason('reason', [])
        self.assertEqual('reason', r.reason)
        self.assertEqual(set(), r.records)
        self.assertFalse(r.lenient)
        self.assertEqual('reason', str(r))

        record = Record.new(
            _make_zone(), '', {'ttl': 300, 'type': 'A', 'value': '1.2.3.4'}
        )
        record.octodns['lenient'] = True
        record.context = 'ctx'
        r2 = ValidationReason('reason2', [record])
        self.assertTrue(r2.lenient)
        self.assertIn('reason2', str(r2))
        self.assertIn('ctx', str(r2))


class TestMailZoneValidator(TestCase):
    def test_mail_validator_init(self):
        v = MailZoneValidator('test')
        self.assertEqual('auto', v.mode)

        v = MailZoneValidator('test', mode='mail')
        self.assertEqual('mail', v.mode)

        v = MailZoneValidator('test', mode='no-mail')
        self.assertEqual('no-mail', v.mode)

        with self.assertRaises(ValueError):
            MailZoneValidator('test', mode='bad')

    def test_mail_mode_success(self):
        zone = _make_zone()
        # MX
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
        zone.add_record(mx)
        # SPF (Mixed Case)
        spf = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': ['V=SPF1 include:example.com -ALL'],
            },
        )
        zone.add_record(spf)
        # DMARC (Mixed Case, Escaped)
        dmarc = _add_record(
            zone,
            '_dmarc',
            {'ttl': 300, 'type': 'TXT', 'values': ['v=DMARC1\\; p=REJECT\\;']},
        )
        zone.add_record(dmarc)

        v = MailZoneValidator('test', mode='mail')
        self.assertEqual([], v.validate(zone))

    def test_mail_mode_failures(self):
        zone = _make_zone()
        v = MailZoneValidator('test', mode='mail')

        # Empty zone
        reasons = v.validate(zone)
        self.assertEqual(3, len(reasons))
        self.assertIn('missing MX records', str(reasons[0]))
        self.assertIn('missing an SPF TXT record', str(reasons[1]))
        self.assertIn('missing a DMARC TXT record', str(reasons[2]))

        # Single MX, Multiple SPF, Missing DMARC policy
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 10, 'exchange': 'mail1.unit.tests.'}],
            },
        )
        zone.add_record(mx)
        spf = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': [
                    'v=spf1 include:a.com ~all',
                    'v=spf1 include:b.com -all',
                ],
            },
        )
        zone.add_record(spf)
        dmarc = _add_record(
            zone, '_dmarc', {'ttl': 300, 'type': 'TXT', 'values': ['v=DMARC1;']}
        )
        zone.add_record(dmarc)

        reasons = v.validate(zone)
        self.assertEqual(3, len(reasons))
        self.assertIn('should have at least 2 values', str(reasons[0]))
        self.assertIn('multiple SPF TXT values', str(reasons[1]))
        self.assertIn('missing a policy', str(reasons[2]))

        # Bad SPF terminator
        zone = _make_zone()
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [
                    {'preference': 10, 'exchange': 'm1.'},
                    {'preference': 20, 'exchange': 'm2.'},
                ],
            },
        )
        zone.add_record(mx)
        spf = _add_record(
            zone,
            '',
            {'ttl': 300, 'type': 'TXT', 'values': ['v=spf1 include:a.com']},
        )
        zone.add_record(spf)
        dmarc = _add_record(
            zone,
            '_dmarc',
            {'ttl': 300, 'type': 'TXT', 'values': ['v=DMARC1; p=none']},
        )
        zone.add_record(dmarc)

        reasons = v.validate(zone)
        self.assertEqual(1, len(reasons))
        self.assertIn('terminate with "~all" or "-all"', str(reasons[0]))

    def test_mail_mode_multiple_txt_values(self):
        zone = _make_zone()
        # MX
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [
                    {'preference': 10, 'exchange': 'm1.'},
                    {'preference': 20, 'exchange': 'm2.'},
                ],
            },
        )
        zone.add_record(mx)
        # SPF among other TXT values
        spf = _add_record(
            zone,
            '',
            {'ttl': 300, 'type': 'TXT', 'values': ['other', 'v=spf1 -all']},
        )
        zone.add_record(spf)
        # DMARC among other TXT values
        dmarc = _add_record(
            zone,
            '_dmarc',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': ['other', 'v=DMARC1; p=reject'],
            },
        )
        zone.add_record(dmarc)

        v = MailZoneValidator('test', mode='mail')
        self.assertEqual([], v.validate(zone))

        # TXT exists but no SPF
        zone = _make_zone()
        zone.add_record(mx)
        txt = _add_record(
            zone, '', {'ttl': 300, 'type': 'TXT', 'values': ['just-some-txt']}
        )
        zone.add_record(txt)
        reasons = v.validate(zone)
        self.assertIn('missing an SPF TXT record', str(reasons[0]))

    def test_no_mail_mode_multiple_txt_values(self):
        zone = _make_zone()
        # Null MX
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 0, 'exchange': '.'}],
            },
        )
        zone.add_record(mx)
        # SPF among other TXT values (should fail because it must be EXACTLY v=spf1 -all)
        spf = _add_record(
            zone,
            '',
            {'ttl': 300, 'type': 'TXT', 'values': ['other', 'v=spf1 -all']},
        )
        zone.add_record(spf)
        # DMARC among other TXT values
        dmarc = _add_record(
            zone,
            '_dmarc',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': ['other', 'v=DMARC1; p=reject'],
            },
        )
        zone.add_record(dmarc)

        v = MailZoneValidator('test', mode='no-mail')
        reasons = v.validate(zone)
        self.assertEqual(2, len(reasons))
        self.assertIn('should have a single strict SPF', str(reasons[0]))
        self.assertIn(
            'should have a DMARC TXT record with "v=DMARC1; p=reject;"',
            str(reasons[1]),
        )

        # Multiple SPF values in one record
        zone = _make_zone()
        zone.add_record(mx)
        spf = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': ['v=spf1 -all', 'v=spf1 -all'],
            },
        )
        zone.add_record(spf)
        dmarc = _add_record(
            zone,
            '_dmarc',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': ['v=DMARC1; p=reject', 'v=DMARC1; p=reject'],
            },
        )
        zone.add_record(dmarc)
        reasons = v.validate(zone)
        self.assertEqual(2, len(reasons))
        self.assertIn('should have a single strict SPF', str(reasons[0]))
        self.assertIn(
            'should have a DMARC TXT record with "v=DMARC1; p=reject;"',
            str(reasons[1]),
        )

        # Mail mode, DMARC TXT exists but no DMARC value
        zone = _make_zone()
        mx_mail = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [
                    {'preference': 10, 'exchange': 'm1.'},
                    {'preference': 20, 'exchange': 'm2.'},
                ],
            },
        )
        zone.add_record(mx_mail)
        txt = _add_record(
            zone, '_dmarc', {'ttl': 300, 'type': 'TXT', 'values': ['other']}
        )
        zone.add_record(txt)
        v_mail = MailZoneValidator('test', mode='mail')
        reasons = v_mail.validate(zone)
        self.assertEqual(2, len(reasons))
        self.assertIn('missing an SPF TXT record', str(reasons[0]))
        self.assertIn('missing a DMARC TXT record', str(reasons[1]))

    def test_no_mail_mode_success(self):
        zone = _make_zone()
        # Null MX
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 0, 'exchange': '.'}],
            },
        )
        zone.add_record(mx)
        # Strict SPF (Mixed Case)
        spf = _add_record(
            zone, '', {'ttl': 300, 'type': 'TXT', 'values': ['V=SPF1 -ALL']}
        )
        zone.add_record(spf)
        # DMARC reject (Mixed Case, Escaped)
        dmarc = _add_record(
            zone,
            '_dmarc',
            {'ttl': 300, 'type': 'TXT', 'values': ['v=DMARC1\\; P=REJECT\\;']},
        )
        zone.add_record(dmarc)

        v = MailZoneValidator('test', mode='no-mail')
        self.assertEqual([], v.validate(zone))

    def test_no_mail_mode_failures(self):
        zone = _make_zone()
        v = MailZoneValidator('test', mode='no-mail')

        # Empty zone
        reasons = v.validate(zone)
        self.assertEqual(3, len(reasons))
        self.assertIn('missing a Null MX record', str(reasons[0]))
        self.assertIn('should have a single strict SPF', str(reasons[1]))
        self.assertIn(
            'should have a DMARC TXT record with "v=DMARC1; p=reject;"',
            str(reasons[2]),
        )

        # Bad MX, Bad SPF, Bad DMARC
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 10, 'exchange': 'mail.'}],
            },
        )
        zone.add_record(mx)
        spf = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'TXT',
                'values': ['v=spf1 include:a.com ~all'],
            },
        )
        zone.add_record(spf)
        dmarc = _add_record(
            zone,
            '_dmarc',
            {'ttl': 300, 'type': 'TXT', 'values': ['v=DMARC1; p=none']},
        )
        zone.add_record(dmarc)

        reasons = v.validate(zone)
        self.assertEqual(3, len(reasons))
        self.assertIn('should have a single Null MX', str(reasons[0]))
        self.assertIn('should have a single strict SPF', str(reasons[1]))
        self.assertIn(
            'should have a DMARC TXT record with "v=DMARC1; p=reject;"',
            str(reasons[2]),
        )

    def test_auto_mode(self):
        # Auto-detects 'mail'
        zone = _make_zone()
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 10, 'exchange': 'mail.'}],
            },
        )
        zone.add_record(mx)
        v = MailZoneValidator('test', mode='auto')
        reasons = v.validate(zone)
        # Should fail mail rules: redundancy, SPF, DMARC
        self.assertIn('should have at least 2 values', str(reasons[0]))
        self.assertIn('missing an SPF TXT record', str(reasons[1]))

        # Auto-detects 'no-mail' with empty MX
        zone = _make_zone()
        reasons = v.validate(zone)
        # Should fail no-mail rules
        self.assertIn('missing a Null MX record', str(reasons[0]))

        # Auto-detects 'no-mail' with Null MX
        mx = _add_record(
            zone,
            '',
            {
                'ttl': 300,
                'type': 'MX',
                'values': [{'preference': 0, 'exchange': '.'}],
            },
        )
        zone.add_record(mx)
        reasons = v.validate(zone)
        # Should fail no-mail rules: SPF, DMARC
        self.assertIn('should have a single strict SPF', str(reasons[0]))

    def test_builtin_registration(self):
        ids = [v.id for v in Zone.validators.available_validators()]
        self.assertIn('mail', ids)
        self.assertNotIn('multi-value-mx', ids)
        self.assertNotIn('apex-spf-presence', ids)

    def test_builtins_in_best_practice_set(self):
        with zone_validators_snapshot():
            Zone.enable_zone_validators({'best-practice'})
            active_ids = [v.id for v in Zone.validators.registered()]
            self.assertIn('mail', active_ids)

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
