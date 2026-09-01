# Example GCP infrastructure for decnique's Terraform account importer.
#
# Produce the account JSON the tool reads with either:
#   terraform show -json > infra.tfstate.json      # resolved state / plan
# or load the equivalent native config directly:
#   account load examples/accounts/infra/infra.tf.json

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
}

variable "project_id" {
  type    = string
  default = "acme-prod"
}

# --- principals -----------------------------------------------------------------------------

resource "google_service_account" "app" {
  project      = var.project_id
  account_id   = "app-runtime"
  display_name = "App runtime"
}

# --- a custom role: least-privilege deployer ------------------------------------------------

resource "google_project_iam_custom_role" "deployer" {
  project     = var.project_id
  role_id     = "deployer"
  title       = "Deployer"
  permissions = [
    "compute.instances.create",
    "compute.instances.delete",
    "compute.instances.get",
  ]
}

# --- IAM grants -----------------------------------------------------------------------------

resource "google_project_iam_member" "owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "user:alice@acme.com"
}

resource "google_project_iam_binding" "key_admins" {
  project = var.project_id
  role    = "roles/iam.serviceAccountKeyAdmin"
  members = [
    "user:bob@acme.com",
    "group:platform@acme.com",
  ]
}

resource "google_project_iam_member" "deployer_binding" {
  project = var.project_id
  role    = google_project_iam_custom_role.deployer.id
  member  = "serviceAccount:${google_service_account.app.email}"
}

# a public grant — the kind of thing a blindspot / public_access check looks for
resource "google_storage_bucket_iam_member" "public_read" {
  bucket = "acme-prod-public-assets"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# --- audit logging: turn on Data Access logs for storage ------------------------------------

resource "google_project_iam_audit_config" "storage_data_access" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
