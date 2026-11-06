from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    assessments = db.relationship("Assessment", backref="user", lazy=True)
    reports = db.relationship("ReportEntry", backref="user", lazy=True)
    audit_events = db.relationship("AuditEvent", backref="user", lazy=True)


class Assessment(db.Model):
    __tablename__ = "assessments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False, default=0)
    sha256 = db.Column(db.String(128), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_label = db.Column(db.String(30), nullable=False, default="Low")
    status = db.Column(db.String(50), nullable=False, default="completed")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    upload_status = db.Column(db.String(50), nullable=False, default="not_requested")
    cloud_object_name = db.Column(db.String(255), default="")
    cloud_bucket = db.Column(db.String(255), default="")

    findings = db.relationship("Finding", backref="assessment", lazy=True)
    cloud_uploads = db.relationship("CloudUploadRecord", backref="assessment", lazy=True)


class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    finding_id = db.Column(db.String(80), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    impact = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    confidence = db.Column(db.String(40), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(40), default="reported")


class ReportEntry(db.Model):
    __tablename__ = "report_entries"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    report_path = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    risk_label = db.Column(db.String(30), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class CloudUploadRecord(db.Model):
    __tablename__ = "cloud_upload_records"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    provider = db.Column(db.String(50), nullable=False, default="GCS")
    bucket_name = db.Column(db.String(255), nullable=False)
    object_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    size_bytes = db.Column(db.Integer, default=0)


class AuditEvent(db.Model):
    __tablename__ = "audit_events"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event_type = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
