"""Trusted message-to-event provenance, separate from untrusted message text."""


def remember(event, chat_id, message_id, kind):
    if not chat_id or not message_id:
        return
    from ..main import connection
    from ..feishu_cards import message_ids

    with connection() as db:
        db.executemany(
            "INSERT INTO feishu_event_messages VALUES (?,?,?,?,?) ON CONFLICT(message_id) DO NOTHING",
            [
                (
                    part_id,
                    str(event["event_id"]),
                    str(event.get("event_value", "1")),
                    chat_id,
                    kind,
                )
                for part_id in message_ids(message_id)
            ],
        )


def event_for_message(message_id, chat_id):
    from ..main import connection
    import json

    with connection() as db:
        row = db.execute(
            "SELECT e.event_json FROM feishu_event_messages m JOIN alert_events e ON e.event_id=m.event_id AND e.event_value=m.event_value WHERE m.message_id=? AND m.chat_id=?",
            (message_id, chat_id),
        ).fetchone()
        if not row:
            row = db.execute(
                "SELECT e.event_json FROM alert_message_links m JOIN alert_events e ON e.event_id=m.event_id AND e.event_value='1' WHERE m.message_id=? AND m.chat_id=?",
                (message_id, chat_id),
            ).fetchone()
    return json.loads(row[0]) if row and row[0] else None
