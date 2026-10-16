#!/bin/sh
# A Terraform saved plan whose values hold refined unknowns ("known after
# apply" with what is known: not null, a string prefix, number and
# length bounds; go-cty msgpack extension 12) and dynamic-typed values,
# for tests/fixtures/external/terraform-plan/refined.tfplan.
# Run (writes /tmp/fixtures/terraform-plan/out/refined.tfplan):
#   mkdir -p /tmp/fixtures/terraform-plan/out
#   cp tests/data/terraform-plan/make_refined.sh /tmp/fixtures/terraform-plan/run.sh
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/terraform-plan:/work -w /work \
#     --entrypoint sh hashicorp/terraform:1.16.6 /work/run.sh
# Only built-in resources (terraform_data), so no provider is downloaded.
set -e
cd /work
rm -rf cfg && mkdir cfg && cd cfg
cat > main.tf <<'X'
resource "terraform_data" "box" {
  input = ["one", "two", "three"]
}

output "prefixed" {
  value = "box-${terraform_data.box.id}"
}

output "how_many" {
  value = length(terraform_data.box.output)
}

output "items" {
  value = [for s in terraform_data.box.output : upper(s)]
}

output "plain" {
  value = 42
}
X
export TF_IN_AUTOMATION=1 CHECKPOINT_DISABLE=1
terraform version
terraform init -input=false -no-color >/dev/null
terraform plan -input=false -no-color -out=/work/out/refined.tfplan >/dev/null
ls -la /work/out
