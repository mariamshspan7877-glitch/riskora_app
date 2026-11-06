import os

from google.cloud import storage


def cloud_is_configured():
    return bool(os.getenv("GCP_PROJECT_ID") and os.getenv("GCS_BUCKET_NAME"))


def get_cloud_status():
    project_id = os.getenv("GCP_PROJECT_ID")
    bucket_name = os.getenv("GCS_BUCKET_NAME")
    if not project_id or not bucket_name:
        return {
            "configured": False,
            "status": "not_configured",
            "project_id": project_id,
            "bucket_name": bucket_name,
            "message": "Google Cloud Storage is not configured. Local analysis remains available.",
            "objects": [],
        }

    try:
        client = storage.Client(project=project_id)
        bucket = client.bucket(bucket_name)
        bucket.reload()
        return {
            "configured": True,
            "status": "available",
            "project_id": project_id,
            "bucket_name": bucket_name,
            "message": "Cloud Storage is configured and reachable.",
            "objects": [],
        }
    except Exception as exc:
        return {
            "configured": True,
            "status": "error",
            "project_id": project_id,
            "bucket_name": bucket_name,
            "message": str(exc),
            "objects": [],
        }


def list_authorized_objects(bucket_name=None):
    project_id = os.getenv("GCP_PROJECT_ID")
    bucket_name = bucket_name or os.getenv("GCS_BUCKET_NAME")
    if not project_id or not bucket_name:
        return []

    try:
        client = storage.Client(project=project_id)
        bucket = client.bucket(bucket_name)
        return [
            {
                "name": blob.name,
                "size": blob.size,
                "updated": blob.updated.strftime("%Y-%m-%d %H:%M:%S") if blob.updated else "unknown",
            }
            for blob in bucket.list_blobs()
        ]
    except Exception:
        return []


def upload_to_bucket(file_path, object_name, bucket_name=None):
    project_id = os.getenv("GCP_PROJECT_ID")
    bucket_name = bucket_name or os.getenv("GCS_BUCKET_NAME")
    if not project_id or not bucket_name:
        raise RuntimeError("Google Cloud Storage is not configured.")

    client = storage.Client(project=project_id)
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(object_name)
    blob.upload_from_filename(file_path)
    return {"bucket": bucket_name, "object_name": object_name, "status": "uploaded"}
