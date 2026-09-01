# Example GCP infrastructure (Terraform) for decnique

`main.tf` is the human-readable infrastructure. Two JSON forms load into the tool:

- `infra.show.json` — `terraform show -json` of the plan (resolved; a plan leaves
  apply-time values, e.g. the service-account email, unknown).
- `infra.tf.json` — the native Terraform JSON config, references resolved to concrete
  values so the whole account (custom role, service-account grant) is present.

Load either with:

    account load examples/accounts/infra/infra.tf.json
    account load examples/accounts/infra/infra.show.json

Regenerate `infra.show.json` from `main.tf`:

    terraform init && terraform plan -out=plan.tfplan && terraform show -json plan.tfplan > infra.show.json
