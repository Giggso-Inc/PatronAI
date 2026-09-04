"""Recall corpus: one structurally valid sample per catalog pattern must
fire. PLAN.md section 11.3. Every sample below is synthetic/fake -- most
are drawn from providers' own published documentation examples.
"""

from __future__ import annotations

import pytest

from apikey_scanner.detect.engine import scan_line

# pattern_id -> a line of code containing one valid (fake) sample.
SAMPLES: dict[str, str] = {
    'aws_access_key_id': 'aws_key = "AKIAQ' + '7ZP4XKM9LWD2FTR"',
    'aws_secret_access_key': 'aws_secret_access_key = "Q7Zp4Xk9' + 'Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5"',
    'gcp_api_key': 'apiKey: "AIzaSyD9Q7Zp4Xk' + '-M2wLd5FtR8bNcQ7Zp4Xk9Lw"',
    'gcp_service_account_key': '"private_key": "-----BEGIN PRIVATE KEY-----\\' + 'nMIIEvQIBADANBg\\n-----END PRIVATE KEY-----\\n"',  # noqa: E501
    'azure_storage_account_key': 'AccountKey=Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks9Lw2M' + 'd5FtR8bNc3Ve6Ha1Jq0Ks9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks==',  # noqa: E501
    'digitalocean_pat': "token = 'dop_v1_aaaaaaaaaaaaaaaaaaaaaaaa" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
    'heroku_api_key': "heroku_api_key = '01234567-" + "89ab-cdef-0123-456789abcdef'",
    'cloudflare_api_token': "cloudflare_token = 'Q7Zp4Xk9Lw" + "2Md5FtR8bNc3Ve6Ha1Jq0Ks9Lw2Md5'",
    'github_pat_classic': 'token = "ghp_Q7Zp4Xk9Lw2M' + 'd5FtR8bNc3Ve6Ha1Jq0Ks8Rt"',
    'github_pat_fine_grained': 'token = "github_pat_Q7Zp4Xk9' + 'Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks9L"',
    'github_oauth_token': 'token = "gho_Q7Zp4Xk9Lw2M' + 'd5FtR8bNc3Ve6Ha1Jq0Ks8Rt"',
    'github_app_token': 'token = "ghu_Q7Zp4Xk9Lw2M' + 'd5FtR8bNc3Ve6Ha1Jq0Ks8Rt"',
    'gitlab_pat': 'token = "glpat-Q7Z' + 'p4Xk9Lw2Md5FtR8bN"',
    'npm_access_token': 'token = "npm_Q7Zp4Xk9Lw2M' + 'd5FtR8bNc3Ve6Ha1Jq0Ks8Rt"',
    'pypi_api_token': 'token = "pypi-AgEIcHlwaS5vcmcQ7Zp4Xk9Lw2' + 'Md5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5Wm9Bx3Cf7U"',
    'dockerhub_pat': 'token = "dckr_pat_Q7Zp4' + 'Xk9Lw2Md5FtR8bNc3Ve6Ha"',
    'terraform_cloud_token': 'token = "Q7Zp4Xk9Lw2Md5.atlasv1.AAAAAAAAAAAAAAAAAAA' + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',  # noqa: E501
    'openai_api_key': 'key = "sk-proj-Q7Zp4Xk9Lw' + '2Md5FtR8bNc3Ve6Ha1Jq0Ks9L"',
    'anthropic_api_key': 'key = "sk-ant-Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks9LQ7Zp4Xk9Lw2' + 'Md5FtR8bNc3Ve6Ha1Jq0Ks9LQ7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks9L"',  # noqa: E501
    'huggingface_token': 'token = "hf_Q7Zp4Xk9Lw2' + 'Md5FtR8bNc3Ve6Ha1Jq0Ks8"',
    'cohere_api_key': 'cohere_key = "Q7Zp4Xk9Lw2Md' + '5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5"',
    'replicate_api_token': 'token = "r8_Q7Zp4Xk9Lw2Md' + '5FtR8bNc3Ve6Ha1Jq0Ks8Rt2"',
    'stripe_live_secret_key': 'key = "sk_live_Q7Zp4Xk9' + 'Lw2Md5FtR8bNc3Ve6Ha1Jq"',
    'stripe_live_restricted_key': 'key = "rk_live_Q7Zp4Xk9' + 'Lw2Md5FtR8bNc3Ve6Ha1Jq"',
    'stripe_live_publishable_key': 'key = "pk_live_Q7Zp4Xk9' + 'Lw2Md5FtR8bNc3Ve6Ha1Jq"',
    'square_access_token': 'token = "sq0atp-Q7Z' + 'p4Xk9Lw2Md5FtR8bNc3"',
    'paypal_braintree_access_token': 'token = "access_token$production$Q7Zp4Xk9' + 'Lw2Md5Ft$Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0K"',  # noqa: E501
    'razorpay_live_key': 'key = "rzp_live' + '_Q7Zp4Xk9Lw2Md5"',
    'slack_bot_token': 'token = "xoxb-1234567890-123' + '4567890-Q7Zp4Xk9Lw2Md5FtR8bN"',
    'slack_user_token': 'token = "xoxp-1234567890-123' + '4567890-Q7Zp4Xk9Lw2Md5FtR8bN"',
    'slack_app_token': 'token = "xapp-1-A012345-1234567890-Q7Zp' + '4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks9Lw2Md5FtR"',
    'slack_webhook_url': 'url = "https://hooks.slack.com/services/T0' + '12ABCDE/B012ABCDE/Q7Zp4Xk9Lw2Md5FtR8bNc3Ve"',
    'twilio_api_key': 'key = "SK0123456789ab' + 'cdef0123456789abcdef"',
    'twilio_account_sid_auth_token': 'twilio auth_token = "012345' + '6789abcdef0123456789abcdef"',
    'sendgrid_api_key': 'key = "SG.Q7Zp4Xk9Lw2Md5FtR8bNc3.Q7Zp4' + 'Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5Wm9"',
    'mailgun_api_key': 'key = "key-0123456789a' + 'bcdef0123456789abcdef"',
    'discord_bot_token': 'token = "MQ7Zp4Xk9Lw2Md5FtR8bNc3V.' + 'Q7Zp4X.Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha"',
    'discord_webhook_url': 'url = "https://discord.com/api/webhooks/123456789012345678/Q' + '7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5Wm9Bx3Cf7Ug1Ov4Dz6Ea"',  # noqa: E501
    'telegram_bot_token': 'token = "123456789:AAQ7Zp4X' + 'k9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks"',
    'datadog_api_key': 'datadog key = "012345678' + '9abcdef0123456789abcdef"',
    'newrelic_license_key': 'key = "Q7Zp4Xk9Lw2Md5FtR' + '8bNc3Ve6Ha1Jq0Ks8RtNRAL"',
    'sentry_dsn': 'dsn = "https://0123456789abcdef012345678' + '9abcdef@o12345.ingest.sentry.io/6789012"',
    'pagerduty_api_key': 'pagerduty_api_key = "' + 'Q7Zp4Xk9Lw2Md5FtR8bN"',
    'segment_write_key': 'segment write_key = "Q7Zp4X' + 'k9Lw2Md5FtR8bNc3Ve6Ha1Jq0K"',
    'notion_api_key': 'key = "secret_Q7Zp4Xk9Lw2Md5F' + 'tR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5Wm9"',
    'airtable_api_key': 'airtable_key = "k' + 'eyQ7Zp4Xk9Lw2Md5"',
    'linear_api_key': 'key = "lin_api_Q7Zp4Xk9Lw2Md' + '5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5"',
    'atlassian_api_token': 'token = "ATATT3Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5Wm9Bx3Cf7Ug1Ov4Dz6Ea8Sp2Hj5T' + 'l9Fq3Rk7Wm1Nc5Bv8Xt2Yg6Zh4Uo9Ip1Al3Ck7Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks8Rt2Yn5Wm9B"',  # noqa: E501
    'asana_pat': 'token = "1234567890123456:Q7Z' + 'p4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0K"',
    'shopify_access_token': 'token = "shpat_012345678' + '9abcdef0123456789abcdef"',
    'algolia_admin_api_key': 'algolia admin_api_key = "Q7Zp' + '4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0K"',
    'jwt': 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0N' + 'TY3ODkwIn0.Q7Zp4Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0Ks9Lw"',
    'private_key_pem': '-----BEGIN RSA ' + 'PRIVATE KEY-----',
    'htpasswd_bcrypt_hash': 'hash = "$2b$12$Q7Zp4Xk9Lw2Md5FtR8b' + 'Nc3Ve6Ha1Jq0Ks8Rt2Yn5Wm9Bx3Cf7Ug1O"',
    'authorization_bearer_header': 'Authorization: Bearer Q7Zp4' + 'Xk9Lw2Md5FtR8bNc3Ve6Ha1Jq0K',
    'basic_auth_in_url': 'url = "https://admin:sup3rSecr3' + 'tPass@internal.example.com/api"',
    'postgres_connection_string': 'db = "postgres://user:sup3rSe' + 'cr3tPass@db.internal:5432/app"',
    'mysql_connection_string': 'db = "mysql://user:sup3rSecr' + '3tPass@db.internal:3306/app"',
    'mongodb_connection_string': 'db = "mongodb+srv://user:sup3rSec' + 'r3tPass@cluster0.mongodb.net/app"',
    'redis_connection_string': 'cache = "redis://:sup3rSecr3' + 'tPass@cache.internal:6379/0"',
    'amqp_connection_string': 'mq = "amqp://user:sup3rSecr3' + 'tPass@mq.internal:5672/vhost"',
}


def test_every_regex_pattern_has_a_recall_sample(catalog):
    from apikey_scanner.catalog.loader import GENERIC_ENTROPY_PATTERN_ID

    non_generic_ids = {pid for pid in catalog.specs if pid != GENERIC_ENTROPY_PATTERN_ID}
    missing = non_generic_ids - SAMPLES.keys()
    assert not missing, f"no recall sample defined for: {sorted(missing)}"


@pytest.mark.parametrize("pattern_id", sorted(SAMPLES.keys()))
def test_pattern_fires_on_its_valid_sample(pattern_id, catalog, base_config):
    line = SAMPLES[pattern_id]
    detections = scan_line(line, 1, catalog, base_config, is_lockfile=False)
    fired = {d.pattern_id for d in detections}
    assert pattern_id in fired, f"{pattern_id} did not fire on: {line!r} (fired: {fired})"
