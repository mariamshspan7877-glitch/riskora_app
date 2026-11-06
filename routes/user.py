import os
from datetime import datetime

from flask import Blueprint, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash

from models import Assessment, AuditEvent, CloudUploadRecord, Finding, ReportEntry, db
from services.audit_service import log_event
from services.cloud_storage import get_cloud_status, list_authorized_objects, upload_to_bucket
from services.report_generator import create_pdf_report
from services.risk_scoring import calculate_risk_score, get_risk_label
from services.security_analysis import ALLOWED_EXTENSIONS, analyze_uploaded_file, safe_filename, validate_uploaded_file

user_bp = Blueprint("user", __name__)


@user_bp.route("/dashboard")
@login_required
def dashboard():
    assessment_count = Assessment.query.filter_by(user_id=current_user.id).count()
    high_risk = Assessment.query.filter_by(user_id=current_user.id).filter(Assessment.risk_score >= 75).count()
    cloud_uploads = CloudUploadRecord.query.filter_by(user_id=current_user.id, status="uploaded").count()
    recent_assessments = Assessment.query.filter_by(user_id=current_user.id).order_by(Assessment.created_at.desc()).limit(5).all()

    buckets = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for item in Assessment.query.filter_by(user_id=current_user.id).all():
        risk_name = item.risk_label.lower()
        if risk_name in buckets:
            buckets[risk_name] += 1

    cloud_status = get_cloud_status()
    return render_template(
        "dashboard.html",
        total_assessments=assessment_count,
        high_risk_count=high_risk,
        cloud_upload_count=cloud_uploads,
        recent_assessments=recent_assessments,
        risk_distribution=buckets,
        cloud_status=cloud_status,
    )


@user_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Please select a file to assess.", "error")
            return render_template("upload.html", allowed_extensions=sorted(ALLOWED_EXTENSIONS))

        try:
            file_info = validate_uploaded_file(uploaded, current_app.config["MAX_UPLOAD_SIZE"])
            uploaded.seek(0)
            analysis = analyze_uploaded_file(uploaded, file_info["extension"])

            stored_name = safe_filename(uploaded.filename)
            base_name, extension = os.path.splitext(stored_name)
            counter = 1
            storage_name = stored_name
            storage_path = os.path.join(current_app.config["UPLOAD_FOLDER"], storage_name)
            while os.path.exists(storage_path):
                storage_name = f"{base_name}_{counter}{extension}"
                storage_path = os.path.join(current_app.config["UPLOAD_FOLDER"], storage_name)
                counter += 1

            os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
            uploaded.save(storage_path)
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("upload.html", allowed_extensions=sorted(ALLOWED_EXTENSIONS))

        findings = analysis["findings"]
        risk_score = calculate_risk_score(findings)
        risk_label = get_risk_label(risk_score)

        assessment = Assessment(
            user_id=current_user.id,
            filename=storage_name,
            original_name=uploaded.filename,
            file_type=analysis["file_type"],
            file_size=analysis["file_size"],
            sha256=analysis["sha256"],
            risk_score=risk_score,
            risk_label=risk_label,
            status="completed",
            upload_status="review_required",
        )
        db.session.add(assessment)
        db.session.flush()

        for item in findings:
            finding = Finding(
                assessment_id=assessment.id,
                finding_id=item.get("id", "finding-unknown"),
                category=item.get("category", "assessment"),
                severity=item.get("severity", "low"),
                title=item.get("title", "Assessment finding"),
                description=item.get("description", "No description available."),
                evidence=item.get("evidence", "Not supplied"),
                impact=item.get("impact", "Impact not available."),
                remediation=item.get("remediation", "Review and document next steps."),
                confidence=item.get("confidence", "Medium"),
                verified=True,
            )
            db.session.add(finding)

        db.session.commit()
        log_event(current_user, "assessment", "file_assessed", "success", f"Assessment created for {uploaded.filename}")
        flash("Assessment complete. Review the findings and risk scoring summary.", "success")
        return redirect(url_for("user.assessment_detail", assessment_id=assessment.id))

    return render_template("upload.html", allowed_extensions=sorted(ALLOWED_EXTENSIONS))


@user_bp.route("/assessments/<int:assessment_id>")
@login_required
def assessment_detail(assessment_id):
    assessment = Assessment.query.filter_by(id=assessment_id, user_id=current_user.id).first_or_404()
    return render_template("assessment_detail.html", assessment=assessment)


@user_bp.route("/assessments/<int:assessment_id>/findings")
@login_required
def assessment_findings(assessment_id):
    assessment = Assessment.query.filter_by(id=assessment_id, user_id=current_user.id).first_or_404()
    return render_template("findings.html", assessment=assessment)


@user_bp.route("/assessments/<int:assessment_id>/download-report")
@login_required
def download_report(assessment_id):
    assessment = Assessment.query.filter_by(id=assessment_id, user_id=current_user.id).first_or_404()
    report_dir = current_app.config["REPORT_FOLDER"]
    os.makedirs(report_dir, exist_ok=True)
    file_path = os.path.join(report_dir, f"riskora_report_{assessment.id}.pdf")
    if not os.path.exists(file_path):
        create_pdf_report(assessment, current_user, file_path)
    return send_file(file_path, as_attachment=True)


@user_bp.route("/assessments/<int:assessment_id>/upload-to-cloud", methods=["POST"])
@login_required
def upload_to_cloud(assessment_id):
    assessment = Assessment.query.filter_by(id=assessment_id, user_id=current_user.id).first_or_404()
    cloud_status = get_cloud_status()
    if not cloud_status["configured"]:
        flash("Google Cloud Storage is not configured in this environment. Local assessment remains available.", "warning")
        return redirect(url_for("user.assessment_detail", assessment_id=assessment.id))

    upload_path = os.path.join(current_app.config["UPLOAD_FOLDER"], assessment.filename)
    if not os.path.exists(upload_path):
        flash("The local file is no longer available for cloud upload.", "error")
        return redirect(url_for("user.assessment_detail", assessment_id=assessment.id))

    try:
        result = upload_to_bucket(upload_path, f"riskora/{current_user.id}/{assessment.id}/{assessment.filename}")
        record = CloudUploadRecord(
            user_id=current_user.id,
            assessment_id=assessment.id,
            provider="GCS",
            bucket_name=result["bucket"],
            object_name=result["object_name"],
            status="uploaded",
            message="Uploaded to Google Cloud Storage after local validation.",
            verified=True,
            size_bytes=assessment.file_size,
        )
        assessment.upload_status = "uploaded"
        assessment.cloud_bucket = result["bucket"]
        assessment.cloud_object_name = result["object_name"]
        db.session.add(record)
        db.session.commit()
        log_event(current_user, "cloud", "upload_attempt", "success", f"Uploaded {assessment.original_name} to GCS")
        flash("Cloud upload verified successfully.", "success")
    except Exception as exc:
        record = CloudUploadRecord(
            user_id=current_user.id,
            assessment_id=assessment.id,
            provider="GCS",
            bucket_name=os.getenv("GCS_BUCKET_NAME", "unknown"),
            object_name=assessment.filename,
            status="failed",
            message=str(exc),
            verified=False,
            size_bytes=assessment.file_size,
        )
        assessment.upload_status = "failed"
        db.session.add(record)
        db.session.commit()
        log_event(current_user, "cloud", "upload_attempt", "failed", str(exc))
        flash(f"Upload failed: {exc}", "error")

    return redirect(url_for("user.assessment_detail", assessment_id=assessment.id))


@user_bp.route("/cloud-storage")
@login_required
def cloud_storage():
    cloud_status = get_cloud_status()
    objects = list_authorized_objects(cloud_status.get("bucket_name")) if cloud_status.get("configured") else []
    return render_template("cloud_storage.html", cloud_status=cloud_status, objects=objects)


@user_bp.route("/reports")
@login_required
def reports():
    report_entries = ReportEntry.query.filter_by(user_id=current_user.id).order_by(ReportEntry.created_at.desc()).all()
    return render_template("reports.html", reports=report_entries)


@user_bp.route("/history")
@login_required
def history():
    query = Assessment.query.filter_by(user_id=current_user.id)
    search = request.args.get("search", "").strip()
    risk_filter = request.args.get("risk", "")
    type_filter = request.args.get("type", "")
    date_filter = request.args.get("date", "")

    if search:
        query = query.filter(Assessment.original_name.ilike(f"%{search}%"))
    if risk_filter:
        query = query.filter(Assessment.risk_label == risk_filter)
    if type_filter:
        query = query.filter(Assessment.file_type == type_filter)
    if date_filter:
        query = query.filter(Assessment.created_at >= datetime.strptime(date_filter, "%Y-%m-%d"))

    assessments = query.order_by(Assessment.created_at.desc()).all()
    return render_template("history.html", assessments=assessments, search=search, risk_filter=risk_filter, type_filter=type_filter, date_filter=date_filter)


@user_bp.route("/audit-log")
@login_required
def audit_log():
    events = AuditEvent.query.filter_by(user_id=current_user.id).order_by(AuditEvent.created_at.desc()).all()
    return render_template("audit_log.html", events=events)


@user_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        if full_name:
            current_user.full_name = full_name
        new_password = request.form.get("new_password", "")
        if new_password:
            if len(new_password) < 8:
                flash("Password must be at least 8 characters long.", "error")
            else:
                current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash("Profile settings updated.", "success")
    return render_template("settings.html", user=current_user)


@user_bp.route("/generate-report/<int:assessment_id>", methods=["POST"])
@login_required
def generate_report(assessment_id):
    assessment = Assessment.query.filter_by(id=assessment_id, user_id=current_user.id).first_or_404()
    report_dir = current_app.config["REPORT_FOLDER"]
    report_path = os.path.join(report_dir, f"riskora_report_{assessment.id}.pdf")
    if not os.path.exists(report_path):
        create_pdf_report(assessment, current_user, report_path)
    entry = ReportEntry.query.filter_by(user_id=current_user.id, assessment_id=assessment.id).first()
    if not entry:
        entry = ReportEntry(
            user_id=current_user.id,
            assessment_id=assessment.id,
            report_path=report_path,
            filename=f"riskora_report_{assessment.id}.pdf",
            risk_label=assessment.risk_label,
            risk_score=assessment.risk_score,
        )
        db.session.add(entry)
        db.session.commit()
    log_event(current_user, "report", "generated", "success", f"PDF generated for assessment {assessment.id}")
    flash("PDF report generated successfully.", "success")
    return redirect(url_for("user.reports"))
