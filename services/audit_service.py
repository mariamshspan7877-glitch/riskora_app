from models import AuditEvent, db


def log_event(user, event_type, action, status, details=None):
    event = AuditEvent(
        user_id=user.id if user else None,
        event_type=event_type,
        action=action,
        status=status,
        details=details,
    )
    db.session.add(event)
    db.session.commit()
    return event
