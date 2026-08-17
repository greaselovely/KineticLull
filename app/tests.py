"""Tests for rejection attribution on the Blocked IPs page.

NginxRejection rows always hold a single client address, while BlockedIP
rows may hold a CIDR produced by subnet aggregation. These cover the join
between the two: containment rather than string equality, single
attribution per rejection, and the CIDR case on the timeline endpoint.
"""

from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from users.models import CustomUser

from .models import AppSettings, BlockedIP, NginxRejection


class RejectionAttributionTestCase(TestCase):
    """Shared fixtures and helpers for the blocked-list rejection views."""

    @classmethod
    def setUpTestData(cls):
        cls.user = CustomUser.objects.create_superuser(
            email='admin@example.com', password='test-password',
        )
        # Otherwise TimezoneCheckMiddleware bounces the first superuser
        # request to the settings page.
        app_settings = AppSettings.load()
        app_settings.timezone = 'UTC'
        app_settings.timezone_configured = True
        app_settings.save()

    def setUp(self):
        self.client.force_login(self.user)

    def block(self, ip_address, **kwargs):
        return BlockedIP.objects.create(ip_address=ip_address, **kwargs)

    def reject(self, ip_address, count=1, hours_ago=1, path='/wp-login.php'):
        """Record `count` rejections from `ip_address` inside the window."""
        stamp = timezone.now() - timedelta(hours=hours_ago)
        for _ in range(count):
            NginxRejection.objects.create(
                ip_address=ip_address, path=path, timestamp=stamp,
            )

    def load_page(self):
        response = self.client.get(reverse('app:blocked_ips'))
        self.assertEqual(response.status_code, 200)
        return response

    def badges(self, response):
        """Per-row rejection counts keyed by the row's blocked ip_address."""
        return {
            item['entry'].ip_address: item['rejection_count']
            for item in response.context['blocked_data']
        }

    def timeline(self, ip, window='30d'):
        response = self.client.get(
            reverse('app:blocked_ip_timeline'), {'ip': ip, 'window': window},
        )
        return response, response.json()


class BlockedIPsViewAttributionTests(RejectionAttributionTestCase):

    def test_cidr_block_claims_member_rejections(self):
        """The core bug: a /24 entry showed 0 for traffic it actually blocks."""
        self.block('185.177.72.0/24')
        self.reject('185.177.72.23', count=7)
        self.reject('185.177.72.99', count=3)

        self.assertEqual(self.badges(self.load_page()), {'185.177.72.0/24': 10})

    def test_exact_match_still_counted(self):
        self.block('1.2.3.4')
        self.reject('1.2.3.4', count=5)

        self.assertEqual(self.badges(self.load_page()), {'1.2.3.4': 5})

    def test_rejection_outside_every_block_is_unattributed(self):
        self.block('10.0.0.0/24')
        self.reject('10.0.0.9', count=4)
        self.reject('203.0.113.7', count=6)

        response = self.load_page()
        self.assertEqual(self.badges(response), {'10.0.0.0/24': 4})
        self.assertEqual(response.context['unattributed_rejections'], 6)

    def test_overlapping_blocks_attribute_to_most_specific(self):
        """A rejection lands on exactly one row: the narrowest containing it."""
        self.block('10.0.0.5')
        self.block('10.0.0.0/24')
        self.reject('10.0.0.5', count=8)

        badges = self.badges(self.load_page())
        self.assertEqual(badges['10.0.0.5'], 8)
        self.assertEqual(badges['10.0.0.0/24'], 0)
        self.assertEqual(sum(badges.values()), 8)

    def test_rejection_outside_a_block_falls_through_to_the_supernet(self):
        """The /32 tiebreak must not swallow siblings in the same /24."""
        self.block('10.0.0.5')
        self.block('10.0.0.0/24')
        self.reject('10.0.0.5', count=2)
        self.reject('10.0.0.6', count=3)

        badges = self.badges(self.load_page())
        self.assertEqual(badges, {'10.0.0.5': 2, '10.0.0.0/24': 3})

    def test_rejections_outside_the_thirty_day_window_are_excluded(self):
        self.block('185.177.72.0/24')
        self.reject('185.177.72.23', count=2, hours_ago=1)
        self.reject('185.177.72.23', count=9, hours_ago=24 * 31)

        response = self.load_page()
        self.assertEqual(self.badges(response), {'185.177.72.0/24': 2})
        self.assertEqual(response.context['total_rejections'], 2)

    def test_malformed_and_ipv6_values_do_not_break_the_page(self):
        """Bad data renders as 0 instead of raising out of the view."""
        self.block('not-an-ip')
        self.block('2001:db8::/32')
        self.block('192.0.2.0/24')
        self.reject('2001:db8::1', count=4)
        self.reject('192.0.2.10', count=2)

        badges = self.badges(self.load_page())
        self.assertEqual(badges['not-an-ip'], 0)
        self.assertEqual(badges['2001:db8::/32'], 4)
        self.assertEqual(badges['192.0.2.0/24'], 2)

    def test_v4_rejection_does_not_land_in_a_v6_block(self):
        """Cross-family containment is False, not an error."""
        self.block('2001:db8::/32')
        self.reject('192.0.2.10', count=3)

        response = self.load_page()
        self.assertEqual(self.badges(response), {'2001:db8::/32': 0})
        self.assertEqual(response.context['unattributed_rejections'], 3)

    def test_badges_reconcile_with_the_footer_total(self):
        """Badges sum to total minus exactly the unblocked bucket."""
        self.block('185.177.72.0/24')
        self.block('45.148.10.0/24')
        self.block('1.2.3.4')
        self.reject('185.177.72.23', count=40)
        self.reject('45.148.10.8', count=12)
        self.reject('1.2.3.4', count=5)
        self.reject('198.51.100.1', count=3)

        response = self.load_page()
        badge_total = sum(self.badges(response).values())
        total = response.context['total_rejections']
        unattributed = response.context['unattributed_rejections']

        self.assertEqual(total, 60)
        self.assertEqual(badge_total, 57)
        self.assertLessEqual(badge_total, total)
        self.assertEqual(total - badge_total, unattributed)
        self.assertEqual(response.context['attributed_rejections'], badge_total)

    def test_requires_superuser(self):
        self.client.force_login(
            CustomUser.objects.create_user(
                email='plain@example.com', password='test-password',
            )
        )
        response = self.client.get(reverse('app:blocked_ips'))
        self.assertEqual(response.status_code, 403)


class BlockedIPTimelineViewTests(RejectionAttributionTestCase):

    def test_cidr_returns_member_rejections(self):
        self.block('185.177.72.0/24')
        self.reject('185.177.72.23', count=6)
        self.reject('185.177.72.99', count=4)

        response, data = self.timeline('185.177.72.0/24')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sum(data['values']), 10)
        self.assertIsNone(data['last_rejection'])

    def test_cidr_excludes_addresses_outside_it(self):
        self.block('185.177.72.0/24')
        self.reject('185.177.72.23', count=6)
        self.reject('185.177.73.23', count=99)

        _, data = self.timeline('185.177.72.0/24')
        self.assertEqual(sum(data['values']), 6)

    def test_non_octet_aligned_prefix_is_exact(self):
        """A /25 must not sweep in the upper half of the /24."""
        self.block('192.0.2.0/25')
        self.reject('192.0.2.10', count=5)
        self.reject('192.0.2.200', count=7)

        _, data = self.timeline('192.0.2.0/25')
        self.assertEqual(sum(data['values']), 5)

    def test_single_address_unchanged(self):
        self.block('1.2.3.4')
        self.reject('1.2.3.4', count=3)
        self.reject('1.2.3.5', count=9)

        _, data = self.timeline('1.2.3.4')
        self.assertEqual(sum(data['values']), 3)

    def test_24h_window_buckets_by_hour(self):
        self.block('185.177.72.0/24')
        self.reject('185.177.72.23', count=2, hours_ago=1)
        self.reject('185.177.72.23', count=5, hours_ago=24 * 5)

        _, data = self.timeline('185.177.72.0/24', window='24h')
        self.assertEqual(len(data['values']), 24)
        self.assertEqual(sum(data['values']), 2)

    def test_empty_window_reports_last_rejection_for_a_cidr(self):
        """The fallback message must see CIDR members too."""
        self.block('185.177.72.0/24')
        self.reject('185.177.72.23', count=3, hours_ago=24 * 40)

        _, data = self.timeline('185.177.72.0/24')
        self.assertEqual(sum(data['values']), 0)
        self.assertIsNotNone(data['last_rejection'])
        self.assertTrue(data['last_rejection']['date'])

    def test_no_records_at_all_has_no_last_rejection(self):
        self.block('185.177.72.0/24')

        _, data = self.timeline('185.177.72.0/24')
        self.assertEqual(sum(data['values']), 0)
        self.assertIsNone(data['last_rejection'])

    def test_ipv6_cidr(self):
        self.block('2001:db8::/32')
        self.reject('2001:db8::1', count=4)
        self.reject('2001:db9::1', count=8)

        _, data = self.timeline('2001:db8::/32')
        self.assertEqual(sum(data['values']), 4)

    def test_malformed_ip_is_rejected_before_the_orm(self):
        response, data = self.timeline("1.2.3.4'; DROP TABLE--")
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', data)

    def test_missing_ip_is_rejected(self):
        response = self.client.get(reverse('app:blocked_ip_timeline'))
        self.assertEqual(response.status_code, 400)
