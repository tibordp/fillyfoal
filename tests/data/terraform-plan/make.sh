#!/bin/sh
# Terraform saved plans for tests/fixtures/external/terraform-plan/.
# Run (writes /tmp/fixtures/terraform-plan/out/{create,update}.tfplan):
#   mkdir -p /tmp/fixtures/terraform-plan/out
#   cp tests/data/terraform-plan/make.sh /tmp/fixtures/terraform-plan/run.sh
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/terraform-plan:/work -w /work \
#     --entrypoint sh hashicorp/terraform:1.16.6 /work/run.sh
# Only built-in resources (terraform_data), so no provider is downloaded.
set -e
cd /work
rm -rf cfg && mkdir cfg && cd cfg
cat > main.tf <<'X'
terraform {
  required_version = ">= 1.5"
}

variable "greeting" {
  type    = string
  default = "hello"
}

locals {
  names = ["alpha", "beta"]
}

resource "terraform_data" "thing" {
  for_each = toset(local.names)
  input    = "${var.greeting}, ${each.key}"
}

resource "terraform_data" "single" {
  input            = { kind = "demo", count = 2 }
  triggers_replace = [var.greeting]
}

output "greetings" {
  value = [for t in terraform_data.thing : t.output]
}

output "secret" {
  value     = "not-really-secret"
  sensitive = true
}
X
export TF_IN_AUTOMATION=1 CHECKPOINT_DISABLE=1
terraform version
terraform init -input=false -no-color >/dev/null
# first plan: create everything (empty prior state)
terraform plan -input=false -no-color -out=/work/out/create.tfplan >/dev/null
# apply, then change a variable so a second plan has replacements and a non-empty prior state
terraform apply -input=false -no-color -auto-approve /work/out/create.tfplan >/dev/null
terraform plan -input=false -no-color -var greeting=hi -out=/work/out/update.tfplan >/dev/null
ls -la /work/out
